using SuperSimpleTcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Server
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        SimpleTcpServer server;
        string clientIp;

        string currentUserLogin = string.Empty;
        string currentUserMD5t = string.Empty;
        string currentUserMD5Password = string.Empty;

        bool authentication = false;

        BigInteger a, A, B, g, p, K;

        RC4 encoder;
        RC4 decoder;

        public MainWindow()
        {
            InitializeComponent();
            server = new SimpleTcpServer("127.0.0.1:9000");
        }

        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (tabItemRegistration.IsSelected)
            {
                enteredUserLogin.Text = String.Empty;
                enteredUserPassword.Password = String.Empty;
                enteredUserPasswordRepeat.Password = String.Empty;

                if (server.IsListening)
                {
                    server.Stop();
                }

                return;
            }

            if (tabItemListening.IsSelected)
            {
                logger.Text = String.Empty;

                server.Events.ClientConnected += Events_ClientConnected;
                server.Events.ClientDisconnected += Events_ClientDisconnected;
                server.Events.DataReceived += Events_DataReceived;
                clientIp = string.Empty;

                btnStartServer.IsEnabled = true;

                //ipPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), port);
                //listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                //Connection();

                return;
            }
        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            string recievedMessage = Encoding.UTF8.GetString(e.Data);

            if (recievedMessage.Contains(Constants.RECIEVE_LOGIN_CODE))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_LOGIN_CODE, "");
                bool loginExists = false;

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Клиент {e.IpPort}> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                using (UserContext db = new UserContext())
                {
                    var users = db.Users;

                    foreach (User u in users)
                    {
                        if (u.Login.Equals(recievedMessage))
                        {
                            if (u.TimeTermEnd.CompareTo(DateTime.Now) < 0)
                            {
                                u.Time = DateTime.Now;
                                u.TimeTermEnd = DateTime.Now.AddDays(7);
                            }                            

                            currentUserLogin = u.Login;
                            currentUserMD5Password = u.Password;
                            currentUserMD5t = GetMD5Hash(u.Time.ToString());
                            loginExists = true;
                        }
                    }
                    db.SaveChanges();
                }

                if (!loginExists)
                {
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        logger.Text += $"<Сервер> : несуществующий логин. Отказано в аутентификации.{Environment.NewLine}";

                        logger.ScrollToEnd();
                        return null;
                    }), null);

                    Send(Constants.REFUSE, "");
                    server.DisconnectClient(e.IpPort);

                    return;
                }
                else
                {
                    Send(Constants.SEND_MD5t_CODE, currentUserMD5t);
                    return;
                }
            }

            if (recievedMessage.Contains(Constants.RECIEVE_MD5HASH_CODE))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_MD5HASH_CODE, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Клиент {e.IpPort}> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                string MD5HashOnServer = currentUserLogin + GetMD5Hash(currentUserMD5Password + currentUserMD5t);

                if (!MD5HashOnServer.Equals(recievedMessage))
                {
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        logger.Text += $"<Сервер> : получена неверная свёртка (пароль неверный). Отказано в аутентификации.{Environment.NewLine}";

                        logger.ScrollToEnd();
                        return null;
                    }), null);

                    Send(Constants.REFUSE, "Отказано в аутентификации.");
                    server.DisconnectClient(e.IpPort);

                    return;
                }
                else
                {
                    Send(Constants.SEND_SUCCESS_AUTHENTICATION, "Поздравляю с аутентификацией!");
                    authentication = true;

                    return;
                }
            }

            if (recievedMessage.Contains(Constants.RECIEVE_START_DH))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_START_DH, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Клиент {e.IpPort}> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                if (authentication)
                {
                    //генерация g a p
                    a = GenerateNumber(64);
                    
                    p = GeneratePrimeNumder(64);
                    while (p == -1)
                    {
                        Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                        {
                            logger.Text += $"<Сервер> : Не смог сгенерировать простое число, попробую ещё.{Environment.NewLine}";

                            logger.ScrollToEnd();
                            return null;
                        }), null);

                        p = GeneratePrimeNumder(64);
                    }

                    g = GeneratePrimeNumder(64);
                    while (!CheckG(p, g))
                    {
                        Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                        {
                            logger.Text += $"<Сервер> : Не смог сгенерировать генератор группы, попробую ещё.{Environment.NewLine}";

                            logger.ScrollToEnd();
                            return null;
                        }), null);

                        g = GeneratePrimeNumder(64);
                    }
                    A = POW(g, a, p);

                    Send(Constants.SEND_A_g_p, $"{A} {g} {p}");
                }
                else
                {
                    Send(Constants.REFUSE, "Отказано в выработке.");
                    server.DisconnectClient(e.IpPort);
                }

                return;
            }

            if (recievedMessage.Contains(Constants.RECIEVE_B))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_B, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Клиент {e.IpPort}> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                B = BigInteger.Parse(recievedMessage);

                K = POW(B, a, p);

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    key.Text = $"Сгенерированный ключ: {K}";
                    return null;
                }), null);

                Send("", $"a = {a},{Environment.NewLine} A = {A},{Environment.NewLine} g = {g},{Environment.NewLine}" +
                    $" p = {p},{Environment.NewLine} B = {B},{Environment.NewLine} K = {K}");

                Send(Constants.SEND_SUCCESS_DIFFIHELLMAN, "Алгоритм Диффи-Хеллмана прошёл отлично!");

                return;
            }

            if (recievedMessage.Contains(Constants.RECEIVE_H_S_e_n))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECEIVE_H_S_e_n, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Клиент {e.IpPort}> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();

                    return null;
                }), null);

                List<string> numbers = recievedMessage.Split(' ').ToList();
                string H = numbers[0];
                List<BigInteger> S = numbers[1].Split('|').Select(BigInteger.Parse).ToList();
                BigInteger exp = BigInteger.Parse(numbers[2]);
                BigInteger n = BigInteger.Parse(numbers[3]);

                string decoded_H = GetMD5Hash(DecodeRSAUTF(S, exp, n)); 

                if (H.Equals(decoded_H))
                {
                    Send(Constants.SEND_SUCCESS_DIGITAL_SIGNATURE, "Поздравляем с проверкой ЭЦП!");
                    byte[] byteKey = Encoding.UTF8.GetBytes(K.ToString());
                    encoder = new RC4(byteKey);
                    decoder = new RC4(byteKey);

                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        btnSendMessage.IsEnabled = true;

                        key.Text += $"{Environment.NewLine}Полученный хэш: {H}{Environment.NewLine}Посчитанный хэш: {decoded_H}";

                        return null;
                    }), null);
                }
                else
                {
                    Send("", $"{H} != {decoded_H}");
                }

                return;
            }

            if (recievedMessage.Contains(Constants.CHAT))
            {
                recievedMessage = recievedMessage.Replace(Constants.CHAT, "");

                byte[] recievedByteMessage = recievedMessage.Split(' ').Select(x => byte.Parse(x)).ToArray();
                byte[] decryptedBytes = decoder.Decode(recievedByteMessage, recievedByteMessage.Length);
                string decryptedString = Encoding.UTF8.GetString(decryptedBytes);

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Клиент {e.IpPort}> : шифр -> {recievedMessage} <-{Environment.NewLine}";
                    logger.Text += $"<Клиент {e.IpPort}> : расшифровка -> {decryptedString} <-{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                return;
            }

            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Клиент {e.IpPort}> : {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";

                logger.ScrollToEnd();
                return null;
            }), null);
        }

        private void Send(string code, string message)
        {
            if (server.IsListening)
            {
                if (!string.IsNullOrEmpty(message) && clientIp != null)
                {
                    server.Send(clientIp, code + message);
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        logger.Text += $"<Сервер> : {message}{Environment.NewLine}";
                        logger.ScrollToEnd();
                        return null;
                    }), null);
                    message = string.Empty;
                }
            }
        }

        private void Events_ClientDisconnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Клиент {e.IpPort} отключился.>{Environment.NewLine}";
                clientIp = null;
                return null;
            }), null);
        }

        private void Events_ClientConnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Клиент {e.IpPort} пробует подключиться.>{Environment.NewLine}";
                clientIp = e.IpPort;
                logger.ScrollToEnd();
                return null;
            }), null);
        }

        private void btnStartServer_Click(object sender, RoutedEventArgs e)
        {
            server.Start();
            logger.Text += $"<Сервер запущен, ожидается подключение...>{Environment.NewLine}";
            btnStartServer.IsEnabled = false;
            logger.ScrollToEnd();
        }

        private void Button_Registration_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrWhiteSpace(enteredUserLogin.Text))
            {
                MessageBox.Show("Введите логин!", "Alter", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            else
            {
                if (String.IsNullOrWhiteSpace(enteredUserPassword.Password))
                {
                    MessageBox.Show("Введите пароль!", "Alter", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                else
                {
                    if (String.IsNullOrWhiteSpace(enteredUserPasswordRepeat.Password))
                    {
                        MessageBox.Show("Введите пароль повторно!", "Alter", MessageBoxButton.OK, MessageBoxImage.Information);
                        return;
                    }
                    else
                    {
                        if (enteredUserPassword.Password.Equals(enteredUserPasswordRepeat.Password))
                        {
                            using (UserContext db = new UserContext())
                            {
                                var users = db.Users;

                                foreach (User u in users)
                                {
                                    if (u.Login.Equals(enteredUserLogin.Text))
                                    {
                                        MessageBox.Show("Данный логин уже используется", "Alter", MessageBoxButton.OK, MessageBoxImage.Information);
                                        return;
                                    }
                                }

                                User user = new User()
                                {
                                    Login = enteredUserLogin.Text,
                                    Password = GetMD5Hash(enteredUserPassword.Password),
                                    Time = DateTime.Now,
                                    TimeTermEnd = DateTime.Now
                                };

                                db.Users.Add(user);
                                db.SaveChanges();
                            }
                        }
                        else
                        {
                            MessageBox.Show("Неверно повторен пароль", "Alter", MessageBoxButton.OK, MessageBoxImage.Information);
                            return;
                        }
                    }
                }
            }
        }

        private void btnSendMessage_Click(object sender, RoutedEventArgs e)
        {
            if (decoder is null || encoder is null)
                return;

            if (string.IsNullOrEmpty(tbSendMessage.Text))
                return;

            string sendingMessage = tbSendMessage.Text;
            byte[] byteSendingMessage = Encoding.UTF8.GetBytes(sendingMessage);
            byte[] byteToSend = encoder.Encode(byteSendingMessage, byteSendingMessage.Length);
            string stringToSend = string.Join(" ", byteToSend.Select(x => x.ToString()));

            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер> : хочет отправить -> {sendingMessage} <-{Environment.NewLine}";
                logger.Text += $"<Сервер> : шифр -> {stringToSend} <-{Environment.NewLine}";
                tbSendMessage.Text = "";
                logger.ScrollToEnd();
                return null;
            }), null);

            Send(Constants.CHAT, stringToSend);
        }

        #region HELP

        public string GetMD5Hash(string input)
        {
            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));

            return Convert.ToBase64String(hash);
        }

        BigInteger GenerateNumber(int bitsCount)
        {
            if (bitsCount < 8)
            {
                Random random = new Random(DateTime.Now.Ticks.GetHashCode());
                BigInteger b = new BigInteger(random.Next((bitsCount - 1) * (bitsCount - 1), bitsCount * bitsCount));

                if (b % 2 == 0)
                {
                    b--;
                }

                return b;
            }

            BigInteger a = new BigInteger(Random512Bits(bitsCount / 8));

            if (a < 0)
            {
                a = -a;
            }

            if (a % 2 == 0)
            {
                a--;
            }

            return a;
        }

        private static byte[] Random512Bits(int count)
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = new byte[count];
                rng.GetBytes(bytes);

                return bytes;
            }
        }

        BigInteger NewNOD(BigInteger A, BigInteger B)
        {
            BigInteger mod = Mod(A, B);

            while (mod != 0)
            {
                A = B;
                B = mod;
                mod = Mod(A, B);
            }

            return B;
        }

        private BigInteger Mod(BigInteger x, BigInteger m)
        {
            return ((x % m) + m) % m;
        }

        BigInteger POW(BigInteger intBase, BigInteger index, BigInteger module)
        {
            string indexCode = ToBinaryString(index).Remove(0, 1);

            BigInteger res = 1;

            foreach (char current in indexCode)
            {
                if (current.Equals('1'))
                {
                    res = Mod(intBase * res * res, module);
                }
                else
                {
                    res = Mod(res * res, module);
                }
            }

            return res;
        }

        public static string ToBinaryString(BigInteger bigint)
        {
            byte[] bytes = bigint.ToByteArray();
            int idx = bytes.Length - 1;

            StringBuilder base2 = new StringBuilder(bytes.Length * 8);

            string binary = Convert.ToString(bytes[idx], 2);

            if (binary[0] != '0' && bigint.Sign == 1)
            {
                base2.Append('0');
            }

            base2.Append(binary);

            for (idx--; idx >= 0; idx--)
            {
                base2.Append(Convert.ToString(bytes[idx], 2).PadLeft(8, '0'));
            }

            return base2.ToString();
        }

        bool TestSoloveyaShtrassena(BigInteger n, BigInteger t)
        {
            for (int i = 0; i < t; i++)
            {
                BigInteger a = GetNumber(n);

                BigInteger r = POW(a, (n - 1) / 2, n);

                if (r == 1 || r == n - 1)
                {
                    BigInteger s = Jacobi(a, n);

                    if (s == 1 || s == -1)
                    {
                        continue;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }

            return true;
        }

        BigInteger GetNumber(BigInteger n)
        {
            Random random = new Random(DateTime.Now.Ticks.GetHashCode());
            bool big = true;

            if (n < 65536)
            {
                big = false;
            }

            BigInteger a = n - 1;

            if (big)
            {
                while (a > n - 2)
                {
                    a = new BigInteger(Random512Bits(random.Next(1, (int)(BigInteger.Log(n) / BigInteger.Log(2) / 8))));
                    if (a < 0)
                    {
                        a = -a;
                    }
                }

                if (a < 2)
                {
                    a = 2;
                }
            }
            else
            {
                a = new BigInteger(random.Next(2, (int)(n - 2)));
            }

            return a;
        }

        BigInteger Jacobi(BigInteger a, BigInteger n)
        {
            if (a == 0 || a == 1)
            {
                return a;
            }
            else
            {
                BigInteger k = 0;
                BigInteger copy_of_a = a;
                BigInteger s;

                while (copy_of_a % 2 == 0)
                {
                    k++;
                    copy_of_a /= 2;
                }

                if (k % 2 == 0)
                {
                    s = 1;
                }
                else
                {
                    s = Mod(n, 8) == 1 || Mod(n, 8) == 7 ? 1 : -1;
                }

                if (Mod(n, 4) == 3 && Mod(copy_of_a, 4) == 3)
                {
                    s = -s;
                }

                if (copy_of_a == 1)
                {
                    return s;
                }
                else
                {
                    return s * Jacobi(Mod(n, copy_of_a), copy_of_a);
                }
            }
        }

        BigInteger GeneratePrimeNumder(int count)
        {
            BigInteger a = GenerateNumber(count);

            int time = (int)(BigInteger.Log(a) / BigInteger.Log(2));

            while ((int)(BigInteger.Log(a) / BigInteger.Log(2) / 8) <= count + 1)
            {
                if (TestSoloveyaShtrassena(a, time))
                {
                    return a;
                }
                else
                {
                    a += 2;
                }

                continue;
            }

            return -1;
        }

        bool CheckG(BigInteger p, BigInteger g)
        {
            BigInteger div = Factorization(p - 1, 2, 2).Item1;
            BigInteger ost = (p - 1) / div;

            if (POW(g, div, p) != 1)
                return true;

            var watch = System.Diagnostics.Stopwatch.StartNew();
            while (watch.Elapsed.TotalSeconds < 30)
            {
                div = Factorization(ost, 2, 2).Item1;
                ost /= div;

                if (POW(g, div, p) != 1)
                    return true;
            }

            return false;
        }

        private Tuple<BigInteger, BigInteger> Factorization(BigInteger n, BigInteger a, BigInteger b)
        {
            BigInteger d = 1;
            BigInteger iteration = 0;

            while (d == 1)
            {
                iteration++;

                a = Mod(a * a + 1, n);
                b = Mod(b * b + 1, n);
                b = Mod(b * b + 1, n);

                if (a == b)
                {
                    return new Tuple<BigInteger, BigInteger>(-1, iteration);
                }

                d = NewNOD(BigInteger.Abs(a - b), n);

                if (d != 1)
                {
                    return new Tuple<BigInteger, BigInteger>(d, iteration);
                }
            }

            return new Tuple<BigInteger, BigInteger>(d, iteration);
        }

        private string DecodeRSA(List<BigInteger> cipher, BigInteger exp, BigInteger n)
        {
            List<BigInteger> decedodeText = new List<BigInteger>();

            foreach (BigInteger c in cipher)
            {
                decedodeText.Add(POW(c, exp, n));
            }

            string decryptedString = Encoding.ASCII.GetString(decedodeText.ToArray().Select(x => byte.Parse(x.ToString())).ToArray());
            //string decryptedString = string.Join("", decedodeText.ToArray().Select(x => x.ToString()));

            return decryptedString;
        }

        private string DecodeRSAUTF(List<BigInteger> cipher, BigInteger exp, BigInteger n)
        {
            List<BigInteger> decedodeText = new List<BigInteger>();

            foreach (BigInteger c in cipher)
            {
                decedodeText.Add(POW(c, exp, n));
            }

            string decryptedString = Encoding.UTF8.GetString(decedodeText.ToArray().Select(x => byte.Parse(x.ToString())).ToArray());

            return decryptedString;
        }

        #endregion
    }
}
