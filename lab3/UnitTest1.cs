using System;
using Xunit;

namespace lab3PasswordHash
{
    public class PasswordHash
    {
        [Fact]
        public void InitRunsWithAlmostNullableParams()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash("test"));
        }

        [Fact]
        public void InitRunsWithCustomParams()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("test", 1488);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash("test"));
        }

        [Fact]
        public void SamePasswordReturnsTrue()
        {
            string password = "test";

            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.True(hash1.Equals(hash2));
        }


        [Fact]
        public void DifferentPasswordReturnsFalse()
        {
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash("test");
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash("test1");
            Assert.False(hash1.Equals(hash2));
        }

        [Fact]
        public void SameInitTwiceReturnsTrue()
        {
            string password = "method";
            string init = "test";
            uint adler = 0;

            IIG.PasswordHashingUtils.PasswordHasher.Init(init, adler);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init(init, adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.True(hash1.Equals(hash2));
        }

        [Fact]
        public void SameSaltReturnsTrue()
        {
            string salt = "test1";
            string password = "test";
            uint adler = 0;

            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, adler);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.True(hash1.Equals(hash2));
        }

        [Fact]
        public void DifferentSaltReturnsFalse()
        {
            uint adler = 0;
            string password = "test";

            IIG.PasswordHashingUtils.PasswordHasher.Init("test", adler);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init("another", adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.False(hash1.Equals(hash2));
        }


        [Fact]
        public void SameAdlerModReturnsTrue()
        {
            uint adler = 0;
            string password = "test";
            string salt = null;

            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, adler);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.True(hash1.Equals(hash2));
        }


        [Fact]
        public void DifferentSmallerAdlerModReturnsFalse()
        {
            string password = "test";
            string salt = null;

            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, 110);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, 111);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.False(hash1.Equals(hash2));
        }

        [Fact]
        public void DifferentAdlerModInInitReturnsFalse()
        {
            string password = "test";
            string salt = null;

            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, 999999999);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, 199999999);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.False(hash1.Equals(hash2));
        }

        [Fact]
        public void SameSaltAdlerModReturnsTrue()
        {
            uint adler = 9999999;
            string password = "test";
            string salt = "test1";

            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, adler);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init(salt, adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.True(hash1.Equals(hash2));
        }

        [Fact]
        public void DifferentSaltAdlerModReturnsFalse()
        {
            uint adler = 9999999;
            string password = "test";

            IIG.PasswordHashingUtils.PasswordHasher.Init("test1fafas", adler);
            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            IIG.PasswordHashingUtils.PasswordHasher.Init("test2sfva", adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password);
            Assert.False(hash1.Equals(hash2));
        }
        
        [Fact]
        public void GetHashWithSameParams()
        {
            uint adler = 1;
            string password = "password";
            string salt = "test";

            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password, salt, adler);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password, salt, adler);
            Assert.True(hash1.Equals(hash2));
        }

        [Fact]
        public void GetHashWithDifferentSaltParams()
        {
            string password = "password";

            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password, "salt");
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password, "test");
            Assert.False(hash1.Equals(hash2));
        }

        [Fact]
        public void GetHashWithDifferentAdlerModParams()
        {
            string password = "password";
            string salt = "test";

            String hash1 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password, salt, 1);
            String hash2 = IIG.PasswordHashingUtils.PasswordHasher.GetHash(password, salt, 222);
            Assert.False(hash1.Equals(hash2));
        }

        [Fact]
        public void GetHashForVeryLongString()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash("kjasfbsjanfkjasnfkjasnfkjnfkjdsanfkjasnkjfdnaksjfnkasnfkjdasnfkjasnkjfdnkjfnaskjfnakjsnfkjdanfkjsanfkjasnfkjsandfkjansdfkasnjnasdkjfnkasjdgnajknfkasdnfkjasnkandfkjasnfkjankjsdfnkjsdnjaklvn akljsvnalksjnklasdnkadjlnaksjfndklsjfnajknflaks"));
        }

        [Fact]
        public void GetHashNullPassword()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.Throws<ArgumentNullException>(() => IIG.PasswordHashingUtils.PasswordHasher.GetHash(null));
        }

        [Fact]
        public void GetHashEmptyPassword()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash(""));
        }

        [Fact]
        public void GetHashUtf8()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash("プログラミングが大好き"));
        }

        [Fact]
        public void GetHashUtfCodes()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash("\u00C4 \uD802\u0033 \u00AE \u0306 \u01FD \u03B2 \uD8FF \uDCFF"));
        }

        [Fact]
        public void GetHashUtf32()
        {
            IIG.PasswordHashingUtils.PasswordHasher.Init("", 0);
            Assert.NotNull(IIG.PasswordHashingUtils.PasswordHasher.GetHash("⛢👩🏽‍🚒🌹🐂🖿🌀🏯"));
        }
    }
}
