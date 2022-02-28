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
            var Getter = "";
            var hash = "";
            DateTime time;

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
                        case "Getter" or "getter" when reader.TokenType == JsonTokenType.String:
                            Getter = reader.GetString();
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

            return new Message(Sender, Getter, messageText, hash, DateTime.Now);
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
