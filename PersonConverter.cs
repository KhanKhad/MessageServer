using System.Text.Json;
using System.Text.Json.Serialization;

namespace MessageServer
{
    public class PersonConverter : JsonConverter<Client>
    {
        public override Client Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string personName = "";
            string OpenKey = "";
            string pass = "";
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
                        case "Password" or "password" when reader.TokenType == JsonTokenType.String:
                            pass = reader.GetString();
                            break;
                    }
                }
            }

            return new Client(personName, OpenKey, pass);
        }
        // сериализуем объект Person в json
        public override void Write(Utf8JsonWriter writer, Client person, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("Token", DecodeEncode.encrypt(person.Token, person.OpenKey));
            writer.WriteEndObject();
        }
    }
}
