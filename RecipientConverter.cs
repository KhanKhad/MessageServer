using System.Text.Json;
using System.Text.Json.Serialization;

namespace MessageServer
{
    public class RecipientConverter : JsonConverter<Recipient>
    {
        public override Recipient Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string personName = "";
            string OpenKey = "";
            string hash = "";
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    var propertyName = reader.GetString();
                    reader.Read();
                    switch (propertyName)
                    {
                        case "Name" or "name" when reader.TokenType == JsonTokenType.String:
                            personName = reader.GetString();
                            break;
                        case "openkey" or "Openkey" or "openKey" or "OpenKey" when reader.TokenType == JsonTokenType.String:
                            OpenKey = reader.GetString();
                            break;
                        case "hashkey" or "hashKey" when reader.TokenType == JsonTokenType.String:
                            hash = reader.GetString();
                            break;
                    }
                }
            }
            return new Recipient( personName, hash, OpenKey);
        }
        // сериализуем объект Person в json
        public override void Write(Utf8JsonWriter writer, Recipient person, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("Token", DecodeEncode.encrypt(person.hashName, person.openkey));
            writer.WriteEndObject();
        }
    }
}

