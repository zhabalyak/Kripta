using System;
using System.Collections.Generic;
using System.Linq;
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
        public MainWindow()
        {
            InitializeComponent();
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
    }
}
