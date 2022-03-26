using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public static class Constants
    {
        //коды для аутентификации
        public const string SEND_LOGIN_CODE = "(LOGIN_CODE)";
        public const string RECIEVE_MD5t_CODE = "(MD5t_CODE)";
        public const string SEND_MD5HASH_CODE = "(MD5HASH_CODE)";
        public const string RECEIVE_SUCCESS_AUTHENTICATION = "(SUCCESS_AUTHENTICATION_CODE)";

        //коды для формирования сеансового ключа
        public const string SEND_START_DH = "(START_DH)";
        public const string RECIEVE_A_g_p = "(A_g_p)";
        public const string SEND_B = "(B)";
        public const string RECEIVE_SUCCESS_DIFFIHELLMAN = "(SUCCESS_DIFFIHELLMAN_CODE)";

        //коды для ЭЦП
        public const string SEND_H_S_e_n = "(H_S_e_n)";
        public const string RECEIVE_SUCCESS_DIGITAL_SIGNATURE = "(SUCCESS_DIGITAL_SIGNATURE)";

        //коды для общения
        public const string CHAT = "(CHAT)";

        public const string REFUSE = "REFUSE";
    }
}
