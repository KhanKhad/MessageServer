using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using MessageServer;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto.Parameters;

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
string publickeypem = DecodeEncode.ExportPublicKey(RsaKey); //получим открытый ключ
string privatekey = RsaKey.ToXmlString(true); //получим закрытый ключ

app.Map("/getkeyxml", async (context) => {
    var response = context.Response;
    response.Headers.ContentType = "application/json; charset=utf-8";
    string responseText = $"{publickey}";
    await response.WriteAsJsonAsync(new { openKey = responseText });
}); //отправляет открытый ключ

app.Map("/getkeypem", async (context) => {
    var response = context.Response;
    response.Headers.ContentType = "application/json; charset=utf-8";
    string responseText = $"{publickeypem}";
    await response.WriteAsJsonAsync(new { openKey = responseText });
});

app.MapGet("/api/user1", async (ApplicationContext db) => await db.UserDB.ToListAsync());
app.MapGet("/api/user2", async (ApplicationContext db) => await db.MessageDB.ToListAsync());
app.MapGet("/api/user3", async (ApplicationContext db) => await db.OperationConfurmTable.ToListAsync());

app.MapGet("/api/users", (ApplicationContext db) => {
    db.Database.EnsureDeleted();
    db.SaveChanges();
});

app.MapPost("/getconfurm", async (ApplicationContext db, HttpContext context) =>
{
    await _getConfurm(db, context.Response, context.Request, publickey, privatekey);
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
    await _SendMessages(db, context.Response, context.Request);
});

app.MapPost("/getmessages", async (ApplicationContext db, HttpContext context) =>
{
    await _GetMessages(db, context.Response, context.Request, publickey, privatekey);
});

app.MapPost("/checkMessagesInfo", async (ApplicationContext db, HttpContext context) =>
{
    await _CheckMessages(db, context.Response, context.Request, publickey, privatekey);
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


/*void Distribution(object? state)
{
    foreach (var message in NeedToSendMessages)
    {
        if (ActiveClients.ContainsKey(message.Recipient))
        {

        }
    }
}*/



async Task _getConfurm(ApplicationContext db, HttpResponse response, HttpRequest request, string _publickey, string _privatekey)
{
    try
    {
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new OperationConfurmConverter(_publickey, _privatekey));
        var operationConfurm = await request.ReadFromJsonAsync<OperationConfurm>(jsonoptions);
        if (operationConfurm == null)
        {
            throw new Exception("Bad Request");
        }
        if(operationConfurm.operationId > 5)
        {
            throw new Exception("Bad operation");
        }
        if (operationConfurm.operationId == 0)
        {
            Datacell? _user = await db.UserDB.FirstOrDefaultAsync(u => u.Name == operationConfurm.hashName);
            if (_user != null)
            {
                throw new Exception("Already Exist");
            }
        }
        
        //db.OperationConfurmTable.RemoveRange(db.OperationConfurmTable.Where(u => u.hashName == operationConfurm.hashName));
        var lastConfurm = db.OperationConfurmTable.FirstOrDefault(u => u.hashName == operationConfurm.hashName);
        if (lastConfurm != null)
        {
            db.OperationConfurmTable.Remove(lastConfurm);
            db.SaveChanges();
        }
        string toClient = DecodeEncode.encrypt(operationConfurm.confurmStringClient + "|" + operationConfurm.confurmStringServer, operationConfurm.openkey);//   
        operationConfurm.openkey = Message.DefaultMessage;
        db.OperationConfurmTable.Add(operationConfurm);
        await db.SaveChangesAsync();
        await response.WriteAsJsonAsync(new { ServerToken =  toClient});
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }

}

async Task _Registration(ApplicationContext db, HttpResponse response, HttpRequest request, string _publicKey, string _privateKey)
{
    try
    {
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new PersonConverter(_publicKey, _privateKey));
        var user = await request.ReadFromJsonAsync<Client>(jsonoptions);
        if (user == null)
        {
            throw new Exception("Некорректные данные");
        }
        string ServerToken = user.Name.Split('|')[0];
        string ClientToken = user.Name.Split('|')[2];
        string ClientName = DecodeEncode.CreateMD5(user.Name.Split('|')[1]);
        string ClientPassword = user.Password.Split('|')[1];

        OperationConfurm? _Token = await db.OperationConfurmTable.FirstOrDefaultAsync(u => u.hashName == ClientName);
        if (_Token == null)
        {
            throw new Exception("WrongOpetarionToken1");
        }
        if (!_Token.CheckOperationId(ServerToken, ClientToken, 0))
        {
            throw new Exception("WrongOpetarionToken2");
        }
        db.OperationConfurmTable.Remove(_Token);
        await db.SaveChangesAsync();

        Datacell ? _user = await db.UserDB.FirstOrDefaultAsync(u => u.Name == ClientName);
        if (_user != null)
        {
            throw new Exception("Already Exist");
        }
        
        db.UserDB.Add(new Datacell { Name = ClientName, Token = user.Token, Password = DecodeEncode.CreateMD5(ClientPassword), OpenKey = user.OpenKey, keyValid = 3, GettedMessages = Message.DefaultMessage, SendedMessages = Message.DefaultMessage });
        
        await db.SaveChangesAsync();
        await response.WriteAsJsonAsync(new { Token = DecodeEncode.encrypt(ServerToken + "|" + user.Token + "|" + ClientToken, user.OpenKey) });
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

        string ServerToken = user.Password.Split('|')[2];
        string ClientToken = user.Password.Split('|')[0];
        string ClientName = DecodeEncode.CreateMD5(user.Name.Split('|')[1]);
        string ClientPassword = DecodeEncode.CreateMD5(user.Password.Split('|')[1]);

        OperationConfurm? _Token = await db.OperationConfurmTable.FirstOrDefaultAsync(u => u.hashName == ClientName);
        if (_Token == null)
        {
            throw new Exception("WrongOpetarionToken1");
        }
        if (!_Token.CheckOperationId(ServerToken, ClientToken, 1))
        {
            throw new Exception("WrongOpetarionToken2");
        }
        db.OperationConfurmTable.Remove(_Token);
        await db.SaveChangesAsync();

        if (user == null)
        {
            throw new Exception("Bad Request");
        }

        Datacell? _user = await db.UserDB.FirstOrDefaultAsync(u => u.Name == ClientName);

        // если не найден, отправляем статусный код и сообщение об ошибке
        if (_user == null)
        {
            throw new Exception("User not found");
        }
        if (!_user.Password.Equals(ClientPassword))
        {
            throw new Exception("Wrong password");
        }

        _user.Token = user.Token;
        _user.OpenKey = user.OpenKey;
        _user.keyValid = 3;
        await db.SaveChangesAsync();
        await response.WriteAsJsonAsync(new { Token = DecodeEncode.encrypt(ClientToken + "|" + user.Token + "|" + ServerToken, user.OpenKey) });
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
        jsonoptions.Converters.Add(new MessageConverter(publickey, privatekey));
        Message? message = await request.ReadFromJsonAsync<Message>(jsonoptions);

        if (message == null)
        {
            throw new Exception("Null message");
        }

        OperationConfurm? _Token = await db.OperationConfurmTable.FirstOrDefaultAsync(u => u.hashName == message.Sender);

        if (_Token == null)
        {
            throw new Exception("WrongOpetarionToken1");
        }

        Datacell? sender = await db.UserDB.FirstOrDefaultAsync(u => u.Name == message.Sender);

        if (sender == null)
        {
            throw new Exception("Unknown sender");
        }

        if (!_Token.CheckCorrectOperation(2, message.hashkey, sender.Token, message.Text))
        {
            throw new Exception("WrongOpetarionToken2");
        }

        Datacell? Recipient = await db.UserDB.FirstOrDefaultAsync(u => u.Name == message.Recipient);

        if (Recipient == null)
        {
            throw new Exception("Unknown Recipient");
        }
        if (Recipient.keyValid == 0)
        {
            throw new Exception("Recipient key is invalid");
        }

        string newId = Message.getid();
        string? gettedMessage = Recipient.GettedMessages;
        string? sendedMessage = sender.SendedMessages;

        if (gettedMessage.Equals(Message.DefaultMessage))
        {
            Recipient.GettedMessages = newId;
        }
        else
        {
            Message? _message = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == gettedMessage);
            _message.lastGettedMessage = newId;
            Recipient.GettedMessages = newId;
        }
        await db.SaveChangesAsync();
        if (sendedMessage.Equals(Message.DefaultMessage))
        {
            sender.SendedMessages = newId;
        }
        else
        {
            Message? _message = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == sendedMessage);
            _message.lastSendedMessage = newId;
            sender.SendedMessages = newId;
        }
        await db.SaveChangesAsync();
        db.MessageDB.Add(new Message { Id = newId, Sender = message.Sender, Recipient = message.Recipient, Text = message.Text, hashkey = message.hashkey, nextGettedMessage = gettedMessage, nextSendedMessage = sendedMessage, lastGettedMessage = Message.DefaultMessage, lastSendedMessage = Message.DefaultMessage, DateTime = message.DateTime, isDelivered = false, isLosted = false, isSended = false, isViewed = false });
        await db.SaveChangesAsync();
        await response.WriteAsJsonAsync(new { message = "Message " + newId +  " sended" });
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
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new RecipientConverter());
        var client = await request.ReadFromJsonAsync<Recipient>(jsonoptions);

        if (client == null)
        {
            throw new Exception("Unknown Recipient1");
        }

        string _Recipient = client.hashName;
        string RecipientKey = client.openkey;
        string hashkey = client.hashKey;

        Datacell? Recipient = await db.UserDB.FirstOrDefaultAsync(u => u.Name == _Recipient);
        
        if (Recipient == null)
        {
            throw new Exception("Unknown Recipient2");
        }

        OperationConfurm? _Token = await db.OperationConfurmTable.FirstOrDefaultAsync(u => u.hashName == _Recipient);

        if (_Token == null)
        {
            throw new Exception("WrongOpetarionToken1");
        }

        if (!_Token.CheckCorrectOperation(3, hashkey, Recipient.Token, _Recipient))
        {
            throw new Exception("WrongOpetarionToken2");
        }


        StringBuilder messages = new StringBuilder();

        string checkMessages = Recipient.GettedMessages;

        while (!checkMessages.Equals(Message.DefaultMessage))
        {
            Message? message = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == checkMessages);
            if (message == null)
            {
                messages.Append("Message losted#");
            }
            else
            {
                if (Recipient.OpenKey.Equals(RecipientKey))
                {
                    if (!message.isSended)
                    {
                        messages.Append(message.DateTime + "|" + message.Id + "|" + message.Sender + "|" + message.Text + "#");
                        message.isSended = true;
                        await db.SaveChangesAsync();
                    }
                }
                else
                {
                    message.isLosted = true;
                    messages.Append("Message " + message.Id + " losted, you key need to upgrade" + "#");
                    await db.SaveChangesAsync();
                }
                checkMessages = message.nextGettedMessage;
            }
        }
        
        await response.WriteAsJsonAsync(new { gettedmessages = messages.ToString().TrimEnd('#') });
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }
}

async Task _CheckMessages(ApplicationContext db, HttpResponse response, HttpRequest request, string _publicKey, string _privateKey)
{
    try
    {
        var jsonoptions = new JsonSerializerOptions();
        jsonoptions.Converters.Add(new PersonConverter(_publicKey, _privateKey));
        var client = await request.ReadFromJsonAsync<Client>(jsonoptions);

        if (client.Name == null)
        {
            throw new Exception("Unknown Sender");
        }

        string _Recipient = client.Name;

        Datacell? Sender = await db.UserDB.FirstOrDefaultAsync(u => u.Name == DecodeEncode.CreateMD5(_Recipient));

        if (Sender == null)
        {
            throw new Exception("Unknown Recipient");
        }

        StringBuilder messages = new StringBuilder();
        string lastSendedMessage = Sender.SendedMessages;
        string checkSendedMessages = Sender.SendedMessages;

        while (!checkSendedMessages.Equals(Message.DefaultMessage))
        {
            Message? Sendedmessage = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == checkSendedMessages);
            if (Sendedmessage == null)
            {
                messages.Append("unknown message#");
            }
            else
            {
                messages.Append(Sendedmessage.Id + "|" + Sendedmessage.isSended + "|" + Sendedmessage.isDelivered + "|" + Sendedmessage.isViewed + "|" + Sendedmessage.isLosted + "#");
                checkSendedMessages = Sendedmessage.nextSendedMessage;
            }
        }
        await response.WriteAsJsonAsync(new { gettedmessages = messages.ToString().TrimEnd('#') });
    }
    catch (Exception e)
    {
        response.StatusCode = 400;
        await response.WriteAsJsonAsync(new { message = e.Message });
    }
}

async Task _DeleteMessage(ApplicationContext db, Message? MessageToDelete)
{
    try
    {
        string lastSendedMessage = MessageToDelete.nextSendedMessage;
        string nextSendedMessage = MessageToDelete.nextSendedMessage;
        string lastGettedMessage = MessageToDelete.nextSendedMessage;
        string nextGettedMessage = MessageToDelete.nextSendedMessage;

        Message? lastsended = null;
        Message? nextsended = null;
        Message? lastgetted = null;
        Message? nextgetted = null;

        if (!lastSendedMessage.Equals(Message.DefaultMessage))
        {
            lastsended = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == lastSendedMessage);
            lastsended.nextSendedMessage = lastGettedMessage;
        }
        if (!nextSendedMessage.Equals(Message.DefaultMessage))
        {
            nextsended = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == nextSendedMessage);
            nextsended.lastSendedMessage = lastSendedMessage;
        }
        if (!lastGettedMessage.Equals(Message.DefaultMessage))
        {
            lastgetted = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == lastGettedMessage);
            lastgetted.nextGettedMessage = nextGettedMessage;
        }
        if (!nextGettedMessage.Equals(Message.DefaultMessage))
        {
            nextgetted = await db.MessageDB.FirstOrDefaultAsync(u => u.Id == nextGettedMessage);
            nextgetted.lastGettedMessage = lastGettedMessage;
        }
        db.MessageDB.Remove(MessageToDelete);
        await db.SaveChangesAsync();
    }
    catch (Exception e)
    {
        Console.WriteLine(e.ToString());
    }
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
    public const string DefaultMessage = "sd";
    public string Id { get; set; }
    public string Sender { get; set; }
    public string Recipient { get; set; }
    public string Text { get; set; }
    public string hashkey { get; set; }
    public string nextGettedMessage { get; set; }
    public string lastGettedMessage { get; set; }
    public string nextSendedMessage { get; set; }
    public string lastSendedMessage { get; set; }
    public bool isLosted { get; set; }
    public bool isSended { get; set; }
    public bool isDelivered { get; set; }
    public bool isViewed { get; set; }
    public string DateTime { get; set; }

    public static string getid()
    {
        return Guid.NewGuid().ToString();
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
    public string GettedMessages { get; set; }
    public string SendedMessages { get; set; }
    public bool checkHashCode(string text, string hash)
    {
        string _hash = DecodeEncode.CreateMD5(Token + text);
        return hash.Equals(_hash);
    }
}
public class OperationConfurm
{
    public int Id { get; set; }
    public int operationId { get; set; }
    //0- регистрация, 1- авторизация, 2- отправка сообщения, 3- получение сообщений
    //4- отправка информации о сообщениях, 5- получение информации об отправленных сообщениях
    public string hashName { get; set; }
    public string confurmStringClient { get; set; }
    public string confurmStringServer { get; set; }
    public string openkey { get; set; }
    public static string getConfurmString()
    {
        return Guid.NewGuid().ToString();
    }
    public bool CheckOperationId(string serverToken, string clientToken, int v)
    {
        return operationId == v && confurmStringServer.Equals(serverToken) && confurmStringClient.Equals(clientToken);
    }

    public bool CheckCorrectOperation(int v, string hash, string clientToken, string enMessage)
    {
        return operationId == v && hash.Equals(DecodeEncode.CreateMD5(clientToken + enMessage + confurmStringServer));
    }
}

public class Recipient
{
    public string hashName { get; set; }
    public string openkey { get; set; }
    public string hashKey { get; set; }

    public Recipient(string name, string hash, string _openkey)
    {
        hashName = name;
        hashKey = hash;
        openkey = _openkey;
    }
}
