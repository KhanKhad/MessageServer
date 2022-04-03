using System.Text.Json;
using System.Text.Json.Serialization;

namespace MessageServer
{
    public class PersonConverter : JsonConverter<Client>
    {
        public string publicKey;
        public string privateKey;
        DecodeEncode _DecodeEncode;

        public PersonConverter(string _publicKey, string _privateKey)
        {
            privateKey = _privateKey;
            publicKey = _publicKey;
            _DecodeEncode = new DecodeEncode(_publicKey, _privateKey);
        }

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

            string clientname = _DecodeEncode.decrypt(personName);
            string clientpass = _DecodeEncode.decrypt(pass);



            return new Client(clientname, OpenKey, clientpass);
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
