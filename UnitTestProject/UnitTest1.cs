using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OAuth.Pack;

namespace UnitTestProject
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void RSATest()
        {
            var rsaParmeters = RSAUtil.GenerateAndSaveKey("E:\\");
        }
    }
}
