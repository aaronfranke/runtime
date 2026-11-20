// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Xunit;

namespace System.Reflection.Emit.Tests
{
    public class ParameterInfoPositionTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        public void MethodParameters_ImplicitAndExplicitPositions(int definedMask)
        {
            var assembly = new PersistedAssemblyBuilder(new AssemblyName("MethodPositions"), typeof(object).Assembly);
            TypeBuilder type = assembly.DefineDynamicModule("MethodPositions").DefineType("Sample");
            MethodBuilder method = type.DefineMethod("Method", MethodAttributes.Public | MethodAttributes.Static,
                typeof(int), new[] { typeof(int), typeof(string), typeof(double) });

            for (int i = 0; i < 3; i++)
            {
                if ((definedMask & (1 << i)) != 0)
                {
                    ParameterBuilder parameter = method.DefineParameter(i + 1, ParameterAttributes.None, "p" + i);
                    Assert.Equal(i + 1, parameter.Position);
                }
            }

            ParameterInfo[] parameters = method.GetParameters();
            Assert.Equal(3, parameters.Length);
            for (int i = 0; i < parameters.Length; i++)
            {
                Assert.Equal(i, parameters[i].Position);
                Assert.Equal((definedMask & (1 << i)) != 0 ? "p" + i : null, parameters[i].Name);
            }

            Assert.Equal(-1, method.ReturnParameter.Position);
            ParameterBuilder result = method.DefineParameter(0, ParameterAttributes.Retval, "result");
            Assert.Equal(0, result.Position);
            Assert.Equal(-1, method.ReturnParameter.Position);
            Assert.Equal("result", method.ReturnParameter.Name);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void ConstructorParameters_ImplicitAndExplicitPositions(int definedMask)
        {
            var assembly = new PersistedAssemblyBuilder(new AssemblyName("ConstructorPositions"), typeof(object).Assembly);
            TypeBuilder type = assembly.DefineDynamicModule("ConstructorPositions").DefineType("Sample");
            ConstructorBuilder constructor = type.DefineConstructor(MethodAttributes.Public, CallingConventions.Standard,
                new[] { typeof(int), typeof(string) });

            for (int i = 0; i < 2; i++)
            {
                if ((definedMask & (1 << i)) != 0)
                {
                    ParameterBuilder parameter = constructor.DefineParameter(i + 1, ParameterAttributes.None, "p" + i);
                    Assert.Equal(i + 1, parameter.Position);
                }
            }

            ParameterInfo[] parameters = constructor.GetParameters();
            Assert.Equal(2, parameters.Length);
            for (int i = 0; i < parameters.Length; i++)
            {
                Assert.Equal(i, parameters[i].Position);
                Assert.Equal((definedMask & (1 << i)) != 0 ? "p" + i : null, parameters[i].Name);
            }
        }
    }
}
