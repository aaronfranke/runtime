// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.ComponentModel.Design;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Reflection;
using Xunit;

namespace System.ComponentModel.Tests
{
    public class LicFileLicenseProviderTests
    {
        [ConditionalTheory(typeof(PlatformDetection), nameof(PlatformDetection.IsWindows))]
        [InlineData(false)]
        [InlineData(true)]
        public void GetLicense_UsesResolverPathWithOrWithoutAssemblyLocation(bool hasLocation)
        {
            Type type = new TestType(hasLocation);
            using var files = new LicenseFiles(type);
            string key = type.FullName + " is a licensed component.";
            File.WriteAllText(files.LicensePath, key + " extra");
            var context = new TestContext(files.ModulePath);
            var provider = new LicFileLicenseProvider();

            using License license = provider.GetLicense(context, type, null, false);
            Assert.NotNull(license);
            Assert.Equal(key, license.LicenseKey);
            Assert.Equal(key, context.SavedKey);
            Assert.Equal(1, context.ResolverCalls);

            File.Delete(files.LicensePath);
            using License cached = provider.GetLicense(context, type, null, false);
            Assert.NotNull(cached);
            Assert.Equal(key, cached.LicenseKey);
            Assert.Equal(1, context.ResolverCalls);
        }

        [Fact]
        public void GetLicense_WithoutAssemblyLocationOrResolver_ReturnsNull()
        {
            var provider = new LicFileLicenseProvider();
            Assert.Null(provider.GetLicense(new TestContext(null), new TestType(false), null, false));
        }

        [Fact]
        public void GetLicense_SavedKeyDoesNotRequireAssemblyLocation()
        {
            Type type = new TestType(false);
            string key = type.FullName + " is a licensed component.";
            var context = new TestContext(null) { SavedKey = key };
            using License license = new LicFileLicenseProvider().GetLicense(context, type, null, false);
            Assert.NotNull(license);
            Assert.Equal(key, license.LicenseKey);
            Assert.Equal(0, context.ResolverCalls);
        }

        private sealed class LicensedComponent { }

        private sealed class TestType(bool hasLocation) : TypeDelegator(typeof(LicensedComponent))
        {
            private readonly Assembly _assembly = new TestAssembly(hasLocation);
            public override Assembly Assembly => _assembly;
            public override Module Module => throw new InvalidOperationException("The resolver path must be used.");
        }

        private sealed class TestAssembly(bool hasLocation) : Assembly
        {
            public override string Location => hasLocation ? "not-used.dll" : string.Empty;
            public override AssemblyName GetName() => typeof(LicensedComponent).Assembly.GetName();
            public override AssemblyName GetName(bool copiedName) => GetName();
        }

        private sealed class TestContext(string modulePath) : LicenseContext, ITypeResolutionService
        {
            public string SavedKey;
            public int ResolverCalls;
            public override string GetSavedLicenseKey(Type type, Assembly resourceAssembly) => SavedKey;
            public override void SetSavedLicenseKey(Type type, string key) => SavedKey = key;
            public override object GetService(Type type) => type == typeof(ITypeResolutionService) && modulePath != null ? this : null;
            public string GetPathOfAssembly(AssemblyName name) { ResolverCalls++; return modulePath; }
            public Assembly GetAssembly(AssemblyName name) => throw new NotSupportedException();
            public Assembly GetAssembly(AssemblyName name, bool throwOnError) => throw new NotSupportedException();
            [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
            public Type GetType([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] string name) => throw new NotSupportedException();
            [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
            public Type GetType([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] string name, bool throwOnError) => throw new NotSupportedException();
            [return: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
            public Type GetType([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] string name, bool throwOnError, bool ignoreCase) => throw new NotSupportedException();
            public void ReferenceAssembly(AssemblyName name) => throw new NotSupportedException();
        }

        private sealed class LicenseFiles : IDisposable
        {
            private readonly string _directory;
            public string LicensePath { get; }
            public string ModulePath => Path.Combine(_directory, "component.dll");

            public LicenseFiles(Type type)
            {
                _directory = Path.Combine(Path.GetTempPath(), "LicFileTests_" + Guid.NewGuid().ToString("N"));
                Assert.False(Directory.Exists(_directory));
                Directory.CreateDirectory(_directory);
                LicensePath = Path.Combine(_directory, type.FullName + ".lic");
                Assert.Equal(Path.GetFullPath(_directory), Path.GetDirectoryName(Path.GetFullPath(LicensePath)));
            }

            public void Dispose()
            {
                File.Delete(LicensePath);
                Directory.Delete(_directory);
            }
        }
    }
}
