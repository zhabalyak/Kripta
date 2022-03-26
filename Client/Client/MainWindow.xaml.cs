using Microsoft.Win32;
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

namespace Client
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        SimpleTcpClient client;

        BigInteger b, B, A, g, p, K;

        private BigInteger rsa_p = 0;
        private BigInteger q = 0;
        private BigInteger n = 0;
        private BigInteger fi_n = 0;
        private BigInteger exp = 0;
        private BigInteger d = 0;

        RC4 encoder;
        RC4 decoder;
        public MainWindow()
        {
            InitializeComponent();

            client = new SimpleTcpClient("127.0.0.1:9000");
            client.Events.Connected += Events_Connected;
            client.Events.DataReceived += Events_DataReceived;
            client.Events.Disconnected += Events_Disconnected;
        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            string recievedMessage = Encoding.UTF8.GetString(e.Data);

            if (recievedMessage.Contains(Constants.REFUSE))
            {
                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер отказал в аутентификации.>{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                return;
            }

            if (recievedMessage.Contains(Constants.RECIEVE_MD5t_CODE))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_MD5t_CODE, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    Send(Constants.SEND_MD5HASH_CODE, enteredUserLogin.Text + GetMD5Hash(GetMD5Hash(enteredUserPassword.Password) + recievedMessage));
                    return null;
                }), null);

                return;
            }

            if (recievedMessage.Contains(Constants.RECEIVE_SUCCESS_AUTHENTICATION))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECEIVE_SUCCESS_AUTHENTICATION, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();

                    gridRegistration.Visibility = Visibility.Collapsed;
                    gridDiffi_Hellman.Visibility = Visibility.Visible;

                    return null;
                }), null);

                return;
            }

            if (recievedMessage.Contains(Constants.RECIEVE_A_g_p))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_A_g_p, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();

                    return null;
                }), null);

                //генерация b B
                List<BigInteger> numbers = recievedMessage.Split(' ').Select(BigInteger.Parse).ToList();
                A = numbers[0];
                g = numbers[1];
                p = numbers[2];

                B = POW(g, b, p);

                K = POW(A, b, p);

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    key.Text = K.ToString();

                    logger.ScrollToEnd();

                    return null;
                }), null);

                Send(Constants.SEND_B, $"{B}");
                Send("", $"A = {A},{Environment.NewLine} g = {g},{Environment.NewLine} p = {p},{Environment.NewLine}" +
                    $" b = {b},{Environment.NewLine} B = {B},{Environment.NewLine} K = {K}");

                return;
            }

            if (recievedMessage.Contains(Constants.RECEIVE_SUCCESS_DIFFIHELLMAN))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECEIVE_SUCCESS_DIFFIHELLMAN, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();

                    gridDiffi_Hellman.Visibility = Visibility.Collapsed;
                    gridDigital_Signature.Visibility = Visibility.Visible;

                    return null;
                }), null);

                return;
            }

            if (recievedMessage.Contains(Constants.RECEIVE_SUCCESS_DIGITAL_SIGNATURE))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECEIVE_SUCCESS_DIGITAL_SIGNATURE, "");

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер> : {recievedMessage}{Environment.NewLine}";

                    logger.ScrollToEnd();

                    gridDigital_Signature.Visibility = Visibility.Collapsed;
                    btnSendMessage.IsEnabled = true;

                    return null;
                }), null);

                byte[] byteKey = Encoding.UTF8.GetBytes(K.ToString());
                encoder = new RC4(byteKey);
                decoder = new RC4(byteKey);

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
                    logger.Text += $"<Сервер> : шифр -> {recievedMessage} <-{Environment.NewLine}";
                    logger.Text += $"<Сервер> : расшифровка -> {decryptedString} <-{Environment.NewLine}";

                    logger.ScrollToEnd();
                    return null;
                }), null);

                return;
            }

            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер> : {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";

                logger.ScrollToEnd();
                return null;
            }), null);
        }

        private void Send(string code, string message)
        {
            if (client.IsConnected)
            {
                if (!string.IsNullOrEmpty(message))
                {
                    client.Send(code + message);
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        logger.Text += $"<{enteredUserLogin.Text}> : {message}{Environment.NewLine}";
                        logger.ScrollToEnd();
                        return null;
                    }), null);
                    message = string.Empty;
                }
            }
        }

        private void Events_Disconnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер отключился.>{Environment.NewLine}";
                logger.ScrollToEnd();
                return null;
            }), null);
        }

        private void Events_Connected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер подключился.>{Environment.NewLine}";
                logger.ScrollToEnd();
                return null;
            }), null);
        }

        private void Button_Connection_Click(object sender, RoutedEventArgs e)
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
                    if (!client.IsConnected)
                    {
                        try
                        {
                            client.Connect();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.Message, "Message", MessageBoxButton.OK, MessageBoxImage.Error);
                        }

                        Send(Constants.SEND_LOGIN_CODE, enteredUserLogin.Text);
                    }
                    else
                    {
                        client = new SimpleTcpClient("127.0.0.1:9000");
                        client.Events.Connected += Events_Connected;
                        client.Events.DataReceived += Events_DataReceived;
                        client.Events.Disconnected += Events_Disconnected;
                        try
                        {
                            client.Connect();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.Message, "Message", MessageBoxButton.OK, MessageBoxImage.Error);
                        }

                        Send(Constants.SEND_LOGIN_CODE, enteredUserLogin.Text);
                    }
                }
            }
        }

        private void btnDiffi_hellman_Click(object sender, RoutedEventArgs e)
        {
            b = GenerateNumber(64);

            Send(Constants.SEND_START_DH, "Готов к совместной выработке сеансового ключа.");
        }

        private void btnDigital_Signature_Click(object sender, RoutedEventArgs e)
        {
            rsa_p = GeneratePrimeNumder(64);
            while (rsa_p == -1)
            {
                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<{enteredUserLogin.Text}> : Не смог сгенерировать простое число p, попробую ещё.{Environment.NewLine}";
                    logger.ScrollToEnd();
                    return null;
                }), null);

                rsa_p = GeneratePrimeNumder(64);
            }

            q = GeneratePrimeNumder(64);
            while (q == -1 || q == p)
            {
                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<{enteredUserLogin.Text}> : Не смог сгенерировать простое число q, попробую ещё.{Environment.NewLine}";
                    logger.ScrollToEnd();
                    return null;
                }), null);

                q = GeneratePrimeNumder(64);
            }

            n = rsa_p * q;
            fi_n = (rsa_p - 1) * (q - 1);

            exp = GenerateNumber(64 * 2 / 3);
            BigInteger y;
            while (NOD(exp, fi_n, out d, out y) != 1)
                exp += 1;

            if (d < 0)
                d += fi_n;

            OpenFileDialog openDialog = new OpenFileDialog();
            openDialog.Title = "Select A File";
            openDialog.Filter = "Text Files (*.txt)|*.txt" + "|" +
                                "Image Files (*.png;*.jpg)|*.png;*.jpg" + "|" +
                                "All Files (*.*)|*.*";
            string file = "test";
            if (openDialog.ShowDialog() == DialogResult.HasValue)
            {
                file = openDialog.FileName;
            }

            string doc = System.IO.File.ReadAllText($"{file}.txt").Replace("\n", " ");

            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<{enteredUserLogin.Text}> : P = {rsa_p}{Environment.NewLine}Q = {q}{Environment.NewLine}" +
                $"N = {n}{Environment.NewLine}Fi_n = {fi_n}{Environment.NewLine}E = {exp}{Environment.NewLine}D = {d}.{Environment.NewLine}";

                tbDigital_Signature.Text = $"P = {rsa_p}{Environment.NewLine}Q = {q}{Environment.NewLine}" +
                $"N = {n}{Environment.NewLine}Fi_n = {fi_n}{Environment.NewLine}E = {exp}{Environment.NewLine}D = {d}" +
                $"{Environment.NewLine}doc = {doc}{Environment.NewLine}";

                logger.ScrollToEnd();

                return null;
            }), null);

            string H = GetMD5Hash(doc);
            List<BigInteger> S = EncodeRSAUTF(doc);
            string send_S = string.Join("|", S);

            Send(Constants.SEND_H_S_e_n, $"{H} {send_S} {exp} {n}");
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
                logger.Text += $"<{enteredUserLogin.Text}> : хочет отправить -> {sendingMessage} <-{Environment.NewLine}";
                logger.Text += $"<{enteredUserLogin.Text}> : шифр -> {stringToSend} <-{Environment.NewLine}";
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

        BigInteger NOD(BigInteger A, BigInteger B, out BigInteger x, out BigInteger y)
        {
            if (B < A)
            {
                BigInteger temp = A;
                A = B;
                B = temp;
            }

            if (A == 0)
            {
                x = 0;
                y = 1;
                return B;
            }

            BigInteger nod = NOD(B % A, A, out x, out y);

            BigInteger newY = x;
            BigInteger newX = y - B / A * x;

            x = newX;
            y = newY;

            return nod;
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

        private List<BigInteger> EncodeRSA(string text)
        {
            List<BigInteger> plainText = Encoding.ASCII.GetBytes(text).Select(x => BigInteger.Parse(x.ToString())).ToList();
            List<BigInteger> encedodeText = new List<BigInteger>();

            foreach (var c in plainText)
            {
                encedodeText.Add(POW(c, d, n));
            }

            return encedodeText;
        }

        private List<BigInteger> EncodeRSAUTF(string text)
        {
            List<BigInteger> plainText = Encoding.UTF8.GetBytes(text).Select(x => BigInteger.Parse(x.ToString())).ToList();
            List<BigInteger> encedodeText = new List<BigInteger>();

            foreach (var c in plainText)
            {
                encedodeText.Add(POW(c, d, n));
            }

            return encedodeText;
        }

        #endregion
    }
}
