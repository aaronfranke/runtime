// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Xunit;

namespace System.Runtime.Serialization.Xml.XsdDataContractExporterTests
{
    public sealed class XsdDataContractExporterRollbackTests
    {
        private const string Namespace = "urn:export-rollback";

        [Theory]
        [InlineData(typeof(System.Collections.Generic.List<>))]
        [InlineData(typeof(ExplicitlyEnumeratedList<>))]
        public void OpenGenericCollection_IsNotExportable(Type type)
        {
            Assert.False(new XsdDataContractExporter().CanExport(type));
            Assert.Throws<InvalidDataContractException>(() => new XsdDataContractExporter().GetSchemaTypeName(type));
            Assert.Throws<InvalidDataContractException>(() => new XsdDataContractExporter().Export(type));
        }

        // Without a public GetEnumerator, the collection contract searches the type's interfaces for
        // IEnumerable<T>, whose FullName is null when T is an unbound generic parameter.
        public class ExplicitlyEnumeratedList<T> : System.Collections.Generic.IList<T>
        {
            public T this[int index] { get => default!; set { } }
            public int Count => 0;
            public bool IsReadOnly => false;
            public void Add(T item) { }
            public void Clear() { }
            public bool Contains(T item) => false;
            public void CopyTo(T[] array, int arrayIndex) { }
            public int IndexOf(T item) => -1;
            public void Insert(int index, T item) { }
            public bool Remove(T item) => false;
            public void RemoveAt(int index) { }
            System.Collections.Generic.IEnumerator<T> System.Collections.Generic.IEnumerable<T>.GetEnumerator() => Enumerable.Empty<T>().GetEnumerator();
            System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => Enumerable.Empty<T>().GetEnumerator();
        }

        private static XsdDataContractExporter PreparedExporter()
        {
            var exporter = new XsdDataContractExporter
            {
                Options = new ExportOptions { DataContractSurrogate = new MappingProvider() }
            };
            exporter.Export(typeof(OpaqueA));
            return exporter;
        }

        private static void ExportSecondType(XsdDataContractExporter exporter)
        {
            exporter.Export(typeof(OpaqueB));
            Assert.NotNull(exporter.Schemas.GlobalTypes[new XmlQualifiedName("B", Namespace)]);
        }

        [Fact]
        public void FailedCanExportType_PreservesSurrogate()
        {
            XsdDataContractExporter exporter = PreparedExporter();
            Assert.False(exporter.CanExport(typeof(System.Collections.Generic.List<>)));
            ExportSecondType(exporter);
        }

        [Fact]
        public void FailedCanExportCollection_PreservesSurrogate()
        {
            XsdDataContractExporter exporter = PreparedExporter();
            Assert.False(exporter.CanExport(new[] { typeof(System.Collections.Generic.List<>) }));
            ExportSecondType(exporter);
        }

        [Fact]
        public void FailedCanExportNullElement_PreservesSurrogate()
        {
            XsdDataContractExporter exporter = PreparedExporter();
            Assert.Throws<ArgumentException>(() => exporter.CanExport(new Type[] { null! }));
            ExportSecondType(exporter);
        }

        [Fact]
        public void FailedExportType_PreservesSurrogate()
        {
            XsdDataContractExporter exporter = PreparedExporter();
            Assert.Throws<InvalidDataContractException>(() => exporter.Export(typeof(System.Collections.Generic.List<>)));
            ExportSecondType(exporter);
        }

        [Fact]
        public void FailedCanExport_PreservesSurrogateAnnotations()
        {
            var exporter = new XsdDataContractExporter
            {
                Options = new ExportOptions { DataContractSurrogate = new AnnotationProvider() }
            };
            Assert.True(exporter.CanExport(typeof(OpaqueA)));
            Assert.False(exporter.CanExport(typeof(System.Collections.Generic.List<>)));
            exporter.Export(typeof(int));
            AssertAnnotations(exporter.Schemas);
        }

        [Fact]
        public void FailedExport_PreservesSurrogateAnnotations()
        {
            var exporter = new XsdDataContractExporter
            {
                Options = new ExportOptions { DataContractSurrogate = new AnnotationProvider() }
            };
            Assert.True(exporter.CanExport(typeof(OpaqueA)));
            Assert.Throws<InvalidDataContractException>(() => exporter.Export(typeof(System.Collections.Generic.List<>)));
            exporter.Export(typeof(int));
            AssertAnnotations(exporter.Schemas);
        }

        private static void AssertAnnotations(XmlSchemaSet schemas)
        {
            XmlSchema schema = schemas.Schemas(Namespace).Cast<XmlSchema>().Single();
            var text = new System.Text.StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(text))
            {
                schema.Write(writer);
            }
            string[] annotations = XDocument.Parse(text.ToString()).Descendants()
                .Where(node => node.Name.LocalName == "Surrogate").Select(node => node.Value).ToArray();
            Assert.Contains("typeA", annotations);
            Assert.Contains("memberA", annotations);
        }

        public sealed class OpaqueA
        {
            public OpaqueA(string value) => Value = value;
            public string Value { get; }
        }
        public sealed class OpaqueB
        {
            public OpaqueB(string value) => Value = value;
            public string Value { get; }
        }
        [DataContract(Name = "A", Namespace = Namespace)]
        public sealed class WireA { [DataMember] public string? Text = null; }
        [DataContract(Name = "B", Namespace = Namespace)]
        public sealed class WireB { [DataMember] public string? Text = null; }

        public class MappingProvider : ISerializationSurrogateProvider
        {
            public Type GetSurrogateType(Type type) => type == typeof(OpaqueA) ? typeof(WireA) : type == typeof(OpaqueB) ? typeof(WireB) : type;
            public object GetObjectToSerialize(object obj, Type targetType) => obj;
            public object GetDeserializedObject(object obj, Type targetType) => obj;
        }
        public sealed class AnnotationProvider : MappingProvider, ISerializationSurrogateProvider2
        {
            public object? GetCustomDataToExport(MemberInfo memberInfo, Type dataContractType) => memberInfo.DeclaringType == typeof(WireA) ? "memberA" : null;
            public object? GetCustomDataToExport(Type runtimeType, Type dataContractType) => runtimeType == typeof(OpaqueA) ? "typeA" : null;
            public void GetKnownCustomDataTypes(Collection<Type> customDataTypes) => customDataTypes.Add(typeof(string));
            public Type? GetReferencedTypeOnImport(string typeName, string typeNamespace, object? customData) => null;
        }
    }
}
