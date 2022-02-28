using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MessageServer;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

Dictionary<string, Client> ActiveClients = new Dictionary<string, Client>();
Dictionary<string, string> PassworDataBase = new Dictionary<string, string>();
List<Message> NeedToSendMessages = new List<Message>();


var builder = WebApplication.CreateBuilder();

// получаем строку подключения из файла конфигурации
string connection = builder.Configuration.GetConnectionString("DefaultConnection");
// добавляем контекст ApplicationContext в качестве сервиса в приложение
builder.Services.AddDbContext<ApplicationContext>(options => options.UseNpgsql(connection));

var app = builder.Build();


app.UseDefaultFiles();
app.UseStaticFiles();

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
app.Map("/getmessages", GetMessages); //получение сообщений по токену, должна быть рассшифровка
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
app.Run();

void GetActiveClients(IApplicationBuilder appBuilder)
{
    appBuilder.Run(async context => await _GetActiveClients(context.Response));
}
void GetMessages(IApplicationBuilder appBuilder)
{

    appBuilder.Run(async context => {
        string Recipient = context.Request.Query["Recipient"];
        await _GetMessages(context.Response, context.Request, ActiveClients.GetValueOrDefault(Recipient));
    });
}


void Distribution(object? state)
{
    foreach (var message in NeedToSendMessages)
    {
        if (ActiveClients.ContainsKey(message.Recipient))
        {

        }
    }
}



async Task _GetActiveClients(HttpResponse response)
{
    await response.WriteAsJsonAsync(ActiveClients);
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
async Task _GetMessages(HttpResponse response, HttpRequest request, Client? user)
{
    try
    {
        if (user == null)
        {
            await response.WriteAsJsonAsync(new { });
        }
        else
        {
            response.ContentType = "text/html; charset=utf-8";

            var stringBuilder = new StringBuilder();
            foreach (var message in user.NeedToGetMessages)
            {
                stringBuilder.Append("From: " + message.Sender + "|" + message.Text);
            }
            await response.WriteAsync(stringBuilder.ToString());
        }
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }

    await response.WriteAsJsonAsync(ActiveClients);
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
    public DateTime DateTime { get; set; }

    public Message(string sender, string recipient, string text)
    {
        Sender = sender;
        Recipient = recipient;
        Text = text;
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

    /*public Datacell(string id, string name, string password, string openKey, int keyvalid)
    {
        Id = id;
        Name = name;
        OpenKey = openKey;
        Password = password;
        keyValid = keyvalid;
    }*/

}
