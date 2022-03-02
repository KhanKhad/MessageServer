using System.Text.Json;
using System.Text.Json.Serialization;

namespace MessageServer
{
    public class MessageConverter : JsonConverter<Message>
    {
        public MessageConverter()
        {
        }

        public override Message Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var messageText = "Undefined";
            var Sender = "";
            var Recipient = "";
            var hash = "";

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    var propertyName = reader.GetString();
                    reader.Read();
                    switch (propertyName)
                    {
                        case "Sender" or "sender" when reader.TokenType == JsonTokenType.String:
                            Sender = reader.GetString();
                            break;
                        case "Recipient" or "recipient" when reader.TokenType == JsonTokenType.String:
                            Recipient = reader.GetString();
                            break;
                        case "Hash" or "hash" when reader.TokenType == JsonTokenType.String:
                            hash = reader.GetString();
                            break;
                        case "messageText" or "MessageText" or "Messagetext" or "messagetext" when reader.TokenType == JsonTokenType.String:
                            messageText = reader.GetString();
                            break;
                    }
                }
            }

            //return new Message(Sender, Recipient, messageText, hash, DateTime.Now);
            return new Message {Id = Guid.NewGuid().ToString(), Sender = Sender, Recipient = Recipient, Text = messageText, DateTime = DateTime.Now.ToString(), hashkey = hash};//  isDelivered = false, isLosted = false, isSended = false, isViewed = false,

        }
        // сериализуем объект Person в json
        public override void Write(Utf8JsonWriter writer, Message message, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("HashKey", message.hashkey);
            writer.WriteEndObject();
        }
    }
}
