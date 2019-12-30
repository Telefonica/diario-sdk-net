namespace DiarioSDKNet
{
    public class Error
    {
        private int code;
        private string message;

        public int Code { get { return code; } }
        public string Message { get { return message; } }

        public Error(int code, string message)
        {
            this.code = code;
            this.message = message;
        }

        public override string ToString()
        {
            return "E" + this.code.ToString() + " - " + message;
        }
    }
}
