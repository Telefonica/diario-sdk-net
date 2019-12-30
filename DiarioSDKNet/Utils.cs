using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace DiarioSDKNet
{
    public static class Utils
    {
        public static string Sha1(HttpPostedFileBase file)
        {
            if (file == null)
            {
                return String.Empty;
            }
            string result = new StreamReader(file.InputStream).ReadToEnd();
            return Sha1(Encoding.UTF8.GetBytes(result));
        }

        public static string Sha1(byte[] data)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                byte[] hash = sha1.ComputeHash(data);
                StringBuilder sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }

                return sb.ToString();
            }
        }
    }
}
