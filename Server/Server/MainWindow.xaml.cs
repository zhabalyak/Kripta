using SuperSimpleTcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
        static int port = 8005;
        static IPEndPoint ipPoint;
        static Socket listenSocket;

        string currentUserLogin = string.Empty;
        string currentUserMD5t = string.Empty;
        string currentUserMD5Password = string.Empty;

        public MainWindow()
        {
            InitializeComponent();
            server = new SimpleTcpServer("127.0.0.1:9000");
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
                            using(UserContext db = new UserContext())
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

        public string GetMD5Hash(string input)
        {
            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));

            return Convert.ToBase64String(hash);
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
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"Клиент {e.IpPort}: {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";
                return null;
            }), null);

            string recievedMessage = Encoding.UTF8.GetString(e.Data);            

            if (recievedMessage.Contains(Constants.RECIEVE_LOGIN_CODE))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_LOGIN_CODE, "");
                bool loginExists = false;

                using (UserContext db = new UserContext())
                {
                    var users = db.Users;

                    foreach (User u in users)
                    {
                        if (u.Login.Equals(recievedMessage))
                        {
                            u.Time = DateTime.Now;
                            u.TimeTermEnd = DateTime.Now.AddDays(7);

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
                        logger.Text += $"Сервер: несуществующий логин. Отказано в аутентификации.{Environment.NewLine}";
                        return null;
                    }), null);

                    Send("REFUSE");
                }
                else
                {
                    Send(Constants.SEND_MD5t_CODE + currentUserMD5t);
                }
            }

            if (recievedMessage.Contains(Constants.RECIEVE_MD5HASH_CODE))
            {
                recievedMessage = recievedMessage.Replace(Constants.RECIEVE_MD5HASH_CODE, "");

                string MD5HashOnServer = currentUserLogin + GetMD5Hash(currentUserMD5Password + currentUserMD5t);

                if (!MD5HashOnServer.Equals(recievedMessage))
                {
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        logger.Text += $"Сервер: получена неверная свёртка (пароль неверный). Отказано в аутентификации.{Environment.NewLine}";
                        return null;
                    }), null);

                    Send("REFUSE");
                }
                else
                {
                    Send("Всё хорошо!");
                }
            }
        }

        private void Events_ClientDisconnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"Клиент {e.IpPort} отключился.{Environment.NewLine}";
                clientIp = null;
                return null;
            }), null);
        }

        private void Events_ClientConnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"Клиент {e.IpPort} пробует подключиться.{Environment.NewLine}";
                clientIp = e.IpPort;
                return null;
            }), null);
        }

        private void Connection()
        {
            try
            {
                listenSocket.Bind(ipPoint);
                listenSocket.Listen(10);

                logger.Text += "\nСервер запущен. Ожидание подключений...";

                Socket handler = listenSocket.Accept();

                StringBuilder builder = new StringBuilder();
                int bytes = 0; // количество полученных байтов
                byte[] data = new byte[256]; // буфер для получаемых данных
                string message = String.Empty;

                #region получение логина
                do
                {
                    bytes = handler.Receive(data);
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (handler.Available > 0);

                if (builder.ToString().Equals("\nСеанс окончен"))
                {
                    logger.Text += "\nПроцесс аутентификации прерван";
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                    return;
                }

                logger.Text += "\n" + DateTime.Now.ToShortTimeString() + ": " + builder.ToString();

                User currentUser = new User();
                bool loginExists = false;

                using (UserContext db = new UserContext())
                {
                    var users = db.Users;

                    foreach (User u in users)
                    {
                        if (u.Login.Equals(builder.ToString()))
                        {
                            u.Time = DateTime.Now;
                            u.TimeTermEnd = DateTime.Now.AddDays(7);
                            db.SaveChanges();

                            currentUser = u;
                            loginExists = true;
                        }
                    }
                }

                if (!loginExists)
                {
                    logger.Text += "\nПроцесс аутентификации прерван: данного логина не существует";

                    message = "Данный логин не существует";
                    data = Encoding.Unicode.GetBytes(message);
                    handler.Send(data);

                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                    return;
                }

                message = GetMD5Hash(currentUser.Time.ToString());
                data = Encoding.Unicode.GetBytes(message);
                handler.Send(data);
                #endregion

                #region получение свёртки
                do
                {
                    bytes = handler.Receive(data);
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (handler.Available > 0);

                if (builder.ToString().Equals("Сеанс окончен"))
                {
                    logger.Text += "\nПроцесс аутентификации прерван";
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                    return;
                }

                logger.Text += "\n" + DateTime.Now.ToShortTimeString() + ": " + builder.ToString();

                if (!builder.ToString().Equals(
                    currentUser.Login +
                    GetMD5Hash(currentUser.Password + GetMD5Hash(currentUser.Time.ToString()))
                    ))
                {
                    logger.Text += "\nПроцесс аутентификации прерван: получена неверная свёртка.";

                    message = "Пароль неверный.";
                    data = Encoding.Unicode.GetBytes(message);
                    handler.Send(data);

                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                    return;
                }

                message = "Аутентификация завершена успешно. Соединение установлено.";
                data = Encoding.Unicode.GetBytes(message);
                handler.Send(data);
                #endregion

                //#region общение с помощью поточного шифра
                //while (true)
                //{
                //    builder.Clear();
                //    do
                //    {
                //        bytes = handler.Receive(data);
                //        builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                //    }
                //    while (handler.Available > 0);

                //    if (builder.ToString().Equals("Сеанс окончен"))
                //        break;

                //    logger.Text += "\n" + DateTime.Now.ToShortTimeString() + ": " + builder.ToString();

                //    // отправляем ответ
                //    message = "ваше сообщение доставлено";
                //    data = Encoding.Unicode.GetBytes(message);
                //    handler.Send(data);
                //}
                //#endregion

                // закрываем сокет
                handler.Shutdown(SocketShutdown.Both);
                handler.Close();
            }
            catch (Exception ex)
            {
                logger.Text += ex.Message;
            }
        }

        SimpleTcpServer server;
        string clientIp;
        private void btnStartServer_Click(object sender, RoutedEventArgs e)
        {
            server.Start();
            logger.Text += $"Сервер запущен, ожидается подключение...{Environment.NewLine}";
            btnStartServer.IsEnabled = false;
        }

        private void Send(string message)
        {
            if (server.IsListening)
            {
                if (!string.IsNullOrEmpty(message) && clientIp != null)
                {
                    server.Send(clientIp, message);
                    Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                    {
                        logger.Text += $"Сервер: {message}{Environment.NewLine}";
                        return null;
                    }), null);
                    message = string.Empty;
                }
            }
        }
    }
}
