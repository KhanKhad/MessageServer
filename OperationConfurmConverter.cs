using System.Text.Json;
using System.Text.Json.Serialization;

namespace MessageServer
{
    public class OperationConfurmConverter : JsonConverter<OperationConfurm>
    {
        public override OperationConfurm Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var operationId = 0;
            var hashName = "";
            var confurmStringClient = "";
            var confurmStringServer = "";

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    var propertyName = reader.GetString();
                    reader.Read();
                    switch (propertyName)
                    {
                        case "operationId" or "operationid" when reader.TokenType == JsonTokenType.String:
                            operationId = reader.GetInt16();
                            break;
                        case "hashName" or "hashname" when reader.TokenType == JsonTokenType.String:
                            hashName = reader.GetString();
                            break;
                        case "confurmStringClient" or "confurmStringClient" or "confurmStringClient" or "confurmStringClient" when reader.TokenType == JsonTokenType.String:
                            confurmStringClient = reader.GetString();
                            break;
                    }
                }
            }

            //return new Message(Sender, Recipient, messageText, hash, DateTime.Now);
            return new OperationConfurm { operationId = operationId, hashName = hashName, confurmStringClient = confurmStringClient, confurmStringServer = OperationConfurm.getConfurmString() };

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
