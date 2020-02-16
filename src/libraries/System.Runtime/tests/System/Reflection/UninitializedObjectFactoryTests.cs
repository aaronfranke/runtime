// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Collections.Tests;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Tests;
using Xunit;

namespace System.Reflection.Tests
{
    public class UninitializedObjectFactoryTests
    {
        [Fact]
        public void CreateInitializedInstance()
        {
            Debugger.Launch();
            Debugger.Break();

            var factory = new ObjectFactory<SampleClass>();
            var retVal = factory.CreateObject();
            Assert.IsType<SampleClass>(retVal);
            Assert.True(retVal.HasInstanceConstructorRun);

            var factory2 = (IObjectFactory)factory;
            var retVal2 = factory2.CreateObject();
            Assert.IsType<SampleClass>(retVal2);
            Assert.True(((SampleClass)retVal2).HasInstanceConstructorRun);
        }

        [Fact]
        public void CreateUninitializedInstance()
        {
            var factory = new UninitializedObjectFactory<SampleClass>();
            var retVal = factory.CreateUninitializedObject();
            Assert.IsType<SampleClass>(retVal);
            Assert.False(retVal.HasInstanceConstructorRun);

            var factory2 = (IUninitializedObjectFactory)factory;
            var retVal2 = factory2.CreateUninitializedObject();
            Assert.IsType<SampleClass>(retVal2);
            Assert.False(((SampleClass)retVal2).HasInstanceConstructorRun);
        }

        private class SampleClass
        {
            public bool HasInstanceConstructorRun = true;
        }
    }
}
