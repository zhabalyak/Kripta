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
        SimpleTcpServer server;
        string clientIp;

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
                            if (u.TimeTermEnd.CompareTo(DateTime.Now) > 0)
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
                        logger.Text += $"Сервер: несуществующий логин. Отказано в аутентификации.{Environment.NewLine}";
                        return null;
                    }), null);

                    Send(Constants.REFUSE);
                    server.DisconnectClient(e.IpPort);
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

                    Send(Constants.REFUSE);
                    server.DisconnectClient(e.IpPort);
                }
                else
                {
                    Send("Поздравляю с аутентификацией");
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
