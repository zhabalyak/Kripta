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

namespace Client
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        SimpleTcpClient client;
        public MainWindow()
        {
            InitializeComponent();

            client = new SimpleTcpClient("127.0.0.1:9000");
            client.Events.Connected += Events_Connected;
            client.Events.DataReceived += Events_DataReceived;
            client.Events.Disconnected += Events_Disconnected;
        }

        private void Events_Disconnected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер отключился.>{Environment.NewLine}";
                return null;
            }), null);
        }

        private void Events_DataReceived(object sender, DataReceivedEventArgs e)
        {
            string recievedMessage = Encoding.UTF8.GetString(e.Data);

            if (recievedMessage.Contains(Constants.REFUSE))
            {
                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    logger.Text += $"<Сервер отказал в аутентификации.>{Environment.NewLine}";
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
                    return null;
                }), null);

                Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
                {
                    Send(Constants.SEND_MD5HASH_CODE, enteredUserLogin.Text + GetMD5Hash(GetMD5Hash(enteredUserPassword.Password) + recievedMessage));
                    return null;
                }), null);

                return;
            }

            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер> : {Encoding.UTF8.GetString(e.Data)}{Environment.NewLine}";
                return null;
            }), null);
        }

        private void Events_Connected(object sender, ConnectionEventArgs e)
        {
            Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new System.Windows.Threading.DispatcherOperationCallback(delegate
            {
                logger.Text += $"<Сервер подключился.>{Environment.NewLine}";
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
                        return null;
                    }), null);
                    message = string.Empty;
                }
            }
        }

        public string GetMD5Hash(string input)
        {
            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));

            return Convert.ToBase64String(hash);
        }
    }
}
