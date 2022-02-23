using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public static class Constants
    {
        //коды для аутентификации
        public const string RECIEVE_LOGIN_CODE = "(LOGIN_CODE)";
        public const string SEND_MD5t_CODE = "(MD5t_CODE)";
        public const string RECIEVE_MD5HASH_CODE = "(MD5HASH_CODE)";

        //коды для формирования сеансового ключа
        public static string SEND_A_g_p = "(A_g_p)";
        public static string RECIEVE_B = "(B)";

        public const string REFUSE = "REFUSE";
    }
}
