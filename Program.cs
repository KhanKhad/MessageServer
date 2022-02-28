using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MessageServer;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

List<Message> NeedToSendMessages = new List<Message>();


var builder = WebApplication.CreateBuilder();

// получаем строку подключения из файла конфигурации
string connection = builder.Configuration.GetConnectionString("DefaultConnection");
// добавляем контекст ApplicationContext в качестве сервиса в приложение
builder.Services.AddDbContext<ApplicationContext>(options => options.UseNpgsql(connection));

var app = builder.Build();


/*TimerCallback tm = new TimerCallback(Distribution);
Timer timer = new Timer(tm, null, 0, 10000);*/

RSACryptoServiceProvider RsaKey = new RSACryptoServiceProvider();
string publickey = RsaKey.ToXmlString(false); //получим открытый ключ
string privatekey = RsaKey.ToXmlString(true); //получим закрытый ключ

app.Map("/getkey", async (context) => {
    var response = context.Response;
    response.Headers.ContentType = "application/json; charset=utf-8";
    string responseText = $"{publickey}";
    await response.WriteAsJsonAsync(new { openKey = responseText });
}); //отправляет открытый ключ

app.Map("/getactiveclients", GetActiveClients); //получения списка активных клиентов, без шифрования
//app.Map("/getmessages", GetMessages); //получение сообщений по токену, должна быть рассшифровка
app.MapGet("/api/users", async (ApplicationContext db) => await db.Users.ToListAsync());
app.MapGet("/api/users1", async (ApplicationContext db) => {
    db.Database.EnsureDeleted();
    db.SaveChanges();
});
app.MapPost("/registration", async (ApplicationContext db, HttpContext context) =>
{
    // добавляем пользователя в массив
    await _Registration(db, context.Response, context.Request, publickey, privatekey);
});
app.MapPost("/authorization", async (ApplicationContext db, HttpContext context) =>
{
    await _Authorization(db, context.Response, context.Request, publickey, privatekey);
});

app.MapPost("/sendmessage", async (ApplicationContext db, HttpContext context) =>
{
    string Sender = context.Request.Query["Sender"];
    await _SendMessages(db, context.Response, context.Request, Sender);
});
app.MapGet("/getmessages", async (ApplicationContext db, HttpContext context) =>
{
    await _GetMessages(db, context.Response, context.Request, publickey, privatekey);
});
app.MapGet("/getuserkey", async (ApplicationContext db, HttpContext context) =>
{
    string Recipient = context.Request.Query["Recipient"];
    Datacell? user = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(Recipient));

    // если не найден, отправляем статусный код и сообщение об ошибке
    if (user == null) return Results.NotFound(new { message = "Пользователь не найден" });
    if (user.keyValid == 0) return Results.NotFound(new { message = "Recipient key is invalid" });
    // если пользователь найден, отправляем его
    return Results.Json(new {openkey =  user.OpenKey });
});
app.Run();

void GetActiveClients(IApplicationBuilder appBuilder)
{
    appBuilder.Run(async context => await _GetActiveClients(context.Response));
}

/*void Distribution(object? state)
{
    foreach (var message in NeedToSendMessages)
    {
        if (ActiveClients.ContainsKey(message.Recipient))
        {

        }
    }
}*/



async Task _GetActiveClients(HttpResponse response)
{
    //await response.WriteAsJsonAsync(ActiveClients);
}
async Task _Registration(ApplicationContext db, HttpResponse response, HttpRequest request, string _publicKey, string _privateKey)
{
    try
    {
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new PersonConverter(_publicKey, _privateKey));
        var user = await request.ReadFromJsonAsync<Client>(jsonoptions);
        if (user != null)
        {
            Datacell? _user = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(user.Name));
            if (_user != null)
            {
                throw new Exception("Already Exist");
            }
            db.Users.Add(new Datacell { Name = DecodeEncode.CreateMD5(user.Name), Token = user.Token, Password = DecodeEncode.CreateMD5(user.Password), OpenKey = user.OpenKey, keyValid = 3 });
            db.SaveChanges();
            await response.WriteAsJsonAsync(user, jsonoptions);
        }
        else
        {
            throw new Exception("Некорректные данные");
        }
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }
}
async Task _Authorization(ApplicationContext db, HttpResponse response, HttpRequest request, string _publicKey, string _privateKey)
{
    try
    {
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new PersonConverter(_publicKey, _privateKey));
        var user = await request.ReadFromJsonAsync<Client>(jsonoptions);

        if (user == null)
        {
            throw new Exception("Bad Request");
        }

        Datacell? _user = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(user.Name));

        // если не найден, отправляем статусный код и сообщение об ошибке
        if (_user == null)
        {
            throw new Exception("User not found");
        }

        _user.Token = user.Token;
        _user.OpenKey = user.OpenKey;
        _user.keyValid = 3;
        await db.SaveChangesAsync();
        await response.WriteAsJsonAsync(new { Token = DecodeEncode.encript(user.Token, user.OpenKey) });
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }
}
async Task _SendMessages(ApplicationContext db, HttpResponse response, HttpRequest request, string _sender)
{
    try
    {
        Datacell? sender = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(_sender));
        if (sender == null)
        {
            throw new Exception("Unknown sender");
        }
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new MessageConverter());
        var message = await request.ReadFromJsonAsync<Message>(jsonoptions);

        if (!checkHashCode(sender.Token, message.Text, message.hashkey))
        {
            throw new Exception("you are not sender");
        }
        Datacell? getter = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(message.Recipient));

        if (getter == null)
        {
            throw new Exception("Unknown Recipient");
        }
        if (getter.keyValid == 0)
        {
            throw new Exception("Recipient key is invalid");
        }

        getter.NeedToGetMessages.Add(message);
        await db.SaveChangesAsync();
        await response.WriteAsJsonAsync(new { message = "Message sended" });
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }
}


async Task _GetMessages(ApplicationContext db, HttpResponse response, HttpRequest request, string _publicKey, string _privateKey)
{
    try
    {
        string Recipient = request.Query["Recipient"];
        DecodeEncode decodeEncode = new DecodeEncode(_publicKey, _privateKey);
        string _Recipient = decodeEncode.decript(Recipient);

        Datacell? getter = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(_Recipient));
        if (getter == null)
        {
            throw new Exception("Unknown Recipient");
        }
        StringBuilder messages = new StringBuilder();

        while(getter.NeedToGetMessages.Count()>0)
        {
            var message = getter.NeedToGetMessages[0];
            Datacell? sender = await db.Users.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(message.Sender));
            messages.Append(message.DateTime+"|"+message.Sender+"|"+message.Text);
            if (sender != null)
            {
                sender.SendedMessages.Add(message.hashkey);
            }
            getter.NeedToGetMessages.RemoveAt(0);
            messages.Append("#");
            await db.SaveChangesAsync();
        }
        await response.WriteAsJsonAsync(new { gettedmessages = messages.ToString().TrimEnd('#') });
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }
}


bool checkHashCode(string token, string text, string hash)
{
    string _hash = DecodeEncode.CreateMD5(token+text);
    return hash.Equals(_hash);  
}

public class Client
{
    public string Token { get; set; }
    public string Name { get; set; }
    public string OpenKey { get; set; }
    public string Password { get; set; }


    public List<Message> NeedToGetMessages = new List<Message>();

    public Client(string name, string openkey, string password)
    {
        Token = Guid.NewGuid().ToString();
        Name = name;
        OpenKey = openkey;
        Password = password;
    }
}
public class Message
{
    public string Sender { get; set; } //кто отправил
    public string Recipient { get; set; } //кто получит
    public string Text { get; set; }
    public string hashkey { get; set; }
    public DateTime DateTime { get; set; }

    public Message(string sender, string recipient, string text, string hash, DateTime time)
    {
        Sender = sender;
        Recipient = recipient;
        Text = text;
        hashkey = hash;
        DateTime = time;
    }

}
public class Datacell
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Token { get; set; }
    public string Password { get; set; }
    public string OpenKey { get; set; }
    public int keyValid { get; set; }
    public List<Message> NeedToGetMessages = new List<Message>();
    public List<string> SendedMessages = new List<string>();
    /*public Datacell(string id, string name, string password, string openKey, int keyvalid)
    {
        Id = id;
        Name = name;
        OpenKey = openKey;
        Password = password;
        keyValid = keyvalid;
    }*/

}
