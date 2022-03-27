using System.Text.Json;
using System.Text.Json.Serialization;

namespace MessageServer
{
    public class OperationConfurmConverter : JsonConverter<OperationConfurm>
    {
        public string publicKey;
        public string privateKey;
        DecodeEncode _DecodeEncode;

        public OperationConfurmConverter(string _publicKey, string _privateKey)
        {
            privateKey = _privateKey;
            publicKey = _publicKey;
            _DecodeEncode = new DecodeEncode(_publicKey, _privateKey);
        }
        public override OperationConfurm Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var operationId = "";
            var hashName = "";
            var confurmStringClient = "";
            var OpenKey = "";

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    var propertyName = reader.GetString();
                    reader.Read();
                    switch (propertyName)
                    {
                        case "operationId" or "operationid" when reader.TokenType == JsonTokenType.String:
                            operationId = reader.GetString();
                            break;
                        case "hashName" or "hashname" when reader.TokenType == JsonTokenType.String:
                            hashName = reader.GetString();
                            break;
                        case "confurmStringClient" or "confurmStringClient" or "confurmStringClient" or "confurmStringClient" when reader.TokenType == JsonTokenType.String:
                            confurmStringClient = reader.GetString();
                            break;
                        case "openkey" or "Openkey" or "openKey" or "OpenKey" when reader.TokenType == JsonTokenType.String:
                            OpenKey = reader.GetString();
                            break;
                    }
                }
            }

            //return new Message(Sender, Recipient, messageText, hash, DateTime.Now);
            return new OperationConfurm { operationId = int.Parse(_DecodeEncode.decrypt(operationId)), hashName = _DecodeEncode.decrypt(hashName), confurmStringClient = _DecodeEncode.decrypt(confurmStringClient), confurmStringServer = OperationConfurm.getConfurmString(), openkey = OpenKey };

        }
        // сериализуем объект Person в json
        public override void Write(Utf8JsonWriter writer, OperationConfurm confurm, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("ConfurmToken", confurm.confurmStringServer);
            writer.WriteEndObject();
        }
    }
}
