using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class RC4
    {
        byte[] S = new byte[256];

        int x = 0;
        int y = 0;

        public RC4(byte[] key)
        {
            init(key);
        }

        // Key-Scheduling Algorithm 
        /// <summary>
        /// Метод инициализации ключевого потока. Заполнение массива S, перестановки элементов, определённые ключом.
        /// </summary>
        /// <param name="key">битовая запись ключа, сгенерированного алгоритмом Диффи-Хеллмана</param>
        private void init(byte[] key)
        {
            int keyLength = key.Length;

            for (int i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + key[i % keyLength]) % 256;
                S.Swap(i, j);
            }
        }

        /// <summary>
        /// Очередной элемент открытого текста складывается по модулю два с очередным элементом ключевого потока
        /// </summary>
        /// <param name="dataB">битовая запись открытого текста</param>
        /// <param name="size">размер битовой записи</param>
        /// <returns></returns>
        public byte[] Encode(byte[] dataB, int size)
        {
            byte[] data = dataB.Take(size).ToArray();

            byte[] cipher = new byte[data.Length];

            for (int m = 0; m < data.Length; m++)
            {
                cipher[m] = (byte)(data[m] ^ keyItem());
            }

            return cipher;
        }

        /// <summary>
        /// обратная операции шифрования - расшифровка
        /// </summary>
        /// <param name="dataB">битовая запись шифротекста</param>
        /// <param name="size">длина битовой записи</param>
        /// <returns></returns>
        public byte[] Decode(byte[] dataB, int size)
        {
            return Encode(dataB, size);
        }

        // Pseudo-Random Generation Algorithm 
        /// <summary>
        /// генерируется очередное слово K - ключ для шифрования/расшифрования. 
        /// Определяются индексы x и y, меняются местами, и по ним получается из массива S очередной ключ
        /// </summary>
        /// <returns></returns>
        private byte keyItem()
        {
            x = (x + 1) % 256;
            y = (y + S[x]) % 256;

            S.Swap(x, y);

            return S[(S[x] + S[y]) % 256];
        }
    }

    static class SwapExt
    {
        public static void Swap<T>(this T[] array, int index1, int index2)
        {
            T temp = array[index1];
            array[index1] = array[index2];
            array[index2] = temp;
        }
    }
}
