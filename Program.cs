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
app.MapGet("/api/users", async (ApplicationContext db) => await db.UserDB.ToListAsync());
app.MapGet("/api/user", async (ApplicationContext db) => await db.MessageDB.ToListAsync());
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
    //string Sender = context.Request.Query["Sender"];
    //await _SendMessages(db, context.Response, context.Request, Sender);
    await _SendMessages(db, context.Response, context.Request);
});
app.MapPost("/getmessages", async (ApplicationContext db, HttpContext context) =>
{
    await _GetMessages(db, context.Response, context.Request, publickey, privatekey);
});
app.MapGet("/getuserkey", async (ApplicationContext db, HttpContext context) =>
{
    string Recipient = context.Request.Query["Recipient"];
    Datacell? user = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(Recipient));

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
            Datacell? _user = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(user.Name));
            if (_user != null)
            {
                throw new Exception("Already Exist");
            }
            db.UserDB.Add(new Datacell { Name = DecodeEncode.CreateMD5(user.Name), Token = user.Token, Password = DecodeEncode.CreateMD5(user.Password), OpenKey = user.OpenKey, keyValid = 3, GettedMessages = "sd", SendedMessages = "sd" });
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

        Datacell? _user = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(user.Name));

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
async Task _SendMessages(ApplicationContext db, HttpResponse response, HttpRequest request)
{
    try
    {
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new MessageConverter());
        Message? message = await request.ReadFromJsonAsync<Message>(jsonoptions);

        
        Datacell? sender = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(message.Sender));

        if (sender == null)
        {
            throw new Exception("Unknown sender");
        }

        if (!checkHashCode(sender.Token, message.Text, message.hashkey))
        {
            throw new Exception("you are not sender");
        }
        Datacell? Recipient = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(message.Recipient));

        if (Recipient == null)
        {
            throw new Exception("Unknown Recipient");
        }
        if (Recipient.keyValid == 0)
        {
            throw new Exception("Recipient key is invalid");
        }
        string newId = getid();
        string? gettedMessage;
        gettedMessage = Recipient.GettedMessages;

        db.MessageDB.Add(new Message {Id =newId, Sender = message.Sender, Recipient = message.Recipient, Text = message.Text, hashkey = message.hashkey, nextMessage = "sd",DateTime = message.DateTime, isDelivered =false, isLosted = false, isSended = false, isViewed = false});
        await db.SaveChangesAsync();

        if (gettedMessage.Equals("sd"))
        {
            Recipient.GettedMessages = newId;
            await db.SaveChangesAsync();
            await response.WriteAsJsonAsync(new { message = "Message sended" });
        }
        else
        {
            Message? _message;
            do
            {
                _message = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == gettedMessage);
                gettedMessage = _message.nextMessage;
            }
            while (!gettedMessage.Equals("sd"));
            _message.nextMessage = newId;
            await db.SaveChangesAsync();
            await response.WriteAsJsonAsync(new { message = "Message sended" });
        }
        
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
        /*string _recipient = request.Query["Recipient"];
        string RecipientKey = request.Query["RecipientKey"];
        DecodeEncode decodeEncode = new DecodeEncode(_publicKey, _privateKey);
        string _Recipient = decodeEncode.decript(_recipient);
         */
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new PersonConverter(_publicKey, _privateKey));
        var client = await request.ReadFromJsonAsync<Client>(jsonoptions);

        if (client.Name == null || client.OpenKey == null)
        {
            throw new Exception("Unknown Recipient, name || openkey == null");
        }

        string _Recipient = client.Name;
        string RecipientKey = client.OpenKey;

        Datacell? Recipient = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(_Recipient));
        
        if (Recipient == null)
        {
            throw new Exception("Unknown Recipient");
        }

        if (!client.OpenKey.Equals(Recipient.OpenKey))
        {
            throw new Exception("You key need to update");
        }
        StringBuilder messages = new StringBuilder();
        while (!Recipient.GettedMessages.Equals("sd"))
        {
            Message? message = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == Recipient.GettedMessages);
            if (message == null)
            {
                throw new Exception("You messages is already deleted");
            }
            Datacell? sender = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(message.Sender));

            if (Recipient.OpenKey.Equals(RecipientKey))
            {
                if (!message.isSended)
                {
                    messages.Append(message.DateTime + "|" + message.Sender + "|" + message.Text + "#");//
                    if (sender != null)
                    {
                        message.isSended = true;
                        //sender.SendedMessages.Add(message.hashkey);
                    }
                }
            }
            else
            {
                if (sender != null)
                {
                    message.isLosted = true;
                    //sender.NotSendedMessages.Add(message.hashkey);
                }
            }
            Recipient.GettedMessages = message.nextMessage;
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

string getid()
{
    return Guid.NewGuid().ToString();
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
    public string Id { get; set; }
    public string Sender { get; set; }
    public string Recipient { get; set; }
    public string Text { get; set; }
    public string hashkey { get; set; }
    public string nextMessage { get; set; }
    public bool isLosted { get; set; }
    public bool isSended { get; set; }
    public bool isDelivered { get; set; }
    public bool isViewed { get; set; }
    public string DateTime { get; set; }

   /*public Message(string sender, string recipient, string text, string hash, DateTime time)
    {
        Sender = sender;
        Recipient = recipient;
        Text = text;
        hashkey = hash;
        DateTime = time;
    }*/

}
public class Datacell
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Token { get; set; }
    public string Password { get; set; }
    public string OpenKey { get; set; }
    public int keyValid { get; set; }
    public string GettedMessages { get; set; }
    public string SendedMessages { get; set; }
    /*public Datacell(string id, string name, string password, string openKey, int keyvalid)
    {
        Id = id;
        Name = name;
        OpenKey = openKey;
        Password = password;
        keyValid = keyvalid;
    }*/

}
