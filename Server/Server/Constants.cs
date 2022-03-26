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
        public const string SEND_SUCCESS_AUTHENTICATION = "(SUCCESS_AUTHENTICATION_CODE)";

        //коды для формирования сеансового ключа
        public const string RECIEVE_START_DH = "(START_DH)";
        public const string SEND_A_g_p = "(A_g_p)";
        public const string RECIEVE_B = "(B)";
        public const string SEND_SUCCESS_DIFFIHELLMAN = "(SUCCESS_DIFFIHELLMAN_CODE)";

        //коды для ЭЦП
        public const string RECEIVE_H_S_e_n = "(H_S_e_n)";
        public const string SEND_SUCCESS_DIGITAL_SIGNATURE = "(SUCCESS_DIGITAL_SIGNATURE)";

        //коды для общения
        public const string CHAT = "(CHAT)";

        public const string REFUSE = "REFUSE";
    }
}
