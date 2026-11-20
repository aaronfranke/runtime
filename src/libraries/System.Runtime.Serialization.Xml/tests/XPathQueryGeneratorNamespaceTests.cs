// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;
using Xunit;

namespace System.Runtime.Serialization.Xml.Tests
{
    public sealed class XPathQueryGeneratorNamespaceTests
    {
        private const string BaseNamespace = "urn:xpath-base";
        private const string MiddleNamespace = "urn:xpath-middle";
        private const string RootNamespace = "urn:xpath-root";
        private const string LeafNamespace = "urn:xpath-leaf-base";

        private static RootDerived Sample() => new()
        {
            Id = 5, Code = "m7", Own = "Rhea", Caption = "hello",
            Child = new NestedDerived { Value = "Oak" }
        };

        private static string Write<T>(T value)
        {
            var text = new StringBuilder();
            using (XmlWriter writer = XmlWriter.Create(text, new XmlWriterSettings { OmitXmlDeclaration = true }))
            {
                new DataContractSerializer(typeof(T)).WriteObject(writer, value);
            }
            return text.ToString();
        }

        private static FieldInfo Field<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] T>(string name) => typeof(T).GetField(name)!;
        private static PropertyInfo Property<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] T>(string name) => typeof(T).GetProperty(name)!;

        private static void AssertSelects<T>(T value, MemberInfo[] members, XName expectedName, string expectedValue)
        {
            string path = XPathQueryGenerator.CreateFromDataContractSerializer(typeof(T), members, out XmlNamespaceManager namespaces);
            XElement? selected = XDocument.Parse(Write(value)).XPathSelectElement(path, namespaces);
            Assert.Equal(expectedName, selected?.Name);
            Assert.Equal(expectedValue, selected?.Value);
        }

        [Fact]
        public void InheritedField_UsesBaseContractNamespace()
        {
            AssertSelects(Sample(), new MemberInfo[] { Field<RootBase>(nameof(RootBase.Id)) }, XName.Get("id", BaseNamespace), "5");
        }

        [Fact]
        public void MultipleBaseLevels_UseEachOwningContractNamespace()
        {
            AssertSelects(Sample(), new MemberInfo[] { Field<RootBase>(nameof(RootBase.Id)) }, XName.Get("id", BaseNamespace), "5");
            AssertSelects(Sample(), new MemberInfo[] { Field<RootMiddle>(nameof(RootMiddle.Code)) }, XName.Get("code", MiddleNamespace), "m7");
        }

        [Fact]
        public void NestedInheritedMembers_UseNamespacesAtBothSteps()
        {
            AssertSelects(Sample(), new MemberInfo[] { Field<RootBase>(nameof(RootBase.Child)), Field<NestedBase>(nameof(NestedBase.Value)) }, XName.Get("value", LeafNamespace), "Oak");
        }

        [Fact]
        public void OverriddenProperty_UsesSerializedBaseMemberNamespace()
        {
            AssertSelects(Sample(), new MemberInfo[] { Property<RootBase>(nameof(RootBase.Caption)) }, XName.Get("caption", BaseNamespace), "hello-override");
            AssertSelects(Sample(), new MemberInfo[] { Property<RootDerived>(nameof(RootDerived.Caption)) }, XName.Get("caption", BaseNamespace), "hello-override");
        }

        [Fact]
        public void CustomRoot_InheritedMemberUsesBaseNamespace()
        {
            var root = new StringBuilder("/wrapper/*[1]");
            string path = XPathQueryGenerator.CreateFromDataContractSerializer(typeof(RootDerived),
                new MemberInfo[] { Field<RootBase>(nameof(RootBase.Id)) }, root, out XmlNamespaceManager namespaces);
            XDocument xml = XDocument.Parse("<wrapper>" + Write(Sample()) + "</wrapper>");
            Assert.Equal("5", xml.XPathSelectElement(path, namespaces)?.Value);
            Assert.Equal(path, root.ToString());
            Assert.StartsWith("/wrapper/*[1]/", path);
        }

        [Fact]
        public void SameNamespaceInheritance_KeepsExistingPrefix()
        {
            var value = new SameDerived { Id = 9 };
            MemberInfo[] members = { Field<SameBase>(nameof(SameBase.Id)) };
            AssertSelects(value, members, XName.Get("id", "urn:xpath-same"), "9");
            string path = XPathQueryGenerator.CreateFromDataContractSerializer(typeof(SameDerived), members, out _);
            Assert.Equal("/xg0:SameDerived/xg0:id", path);
        }

        [Fact]
        public void DirectAndEmptyPaths_KeepDerivedContract()
        {
            AssertSelects(Sample(), new MemberInfo[] { Field<RootDerived>(nameof(RootDerived.Own)) }, XName.Get("own_x0020_name", RootNamespace), "Rhea");
            string path = XPathQueryGenerator.CreateFromDataContractSerializer(typeof(RootDerived), Array.Empty<MemberInfo>(), out XmlNamespaceManager namespaces);
            Assert.Equal("/xg0:Derived", path);
            Assert.Equal(XName.Get("Derived", RootNamespace), XDocument.Parse(Write(Sample())).XPathSelectElement(path, namespaces)?.Name);
        }

        [Fact]
        public void InvalidPaths_StillReject()
        {
            Assert.Throws<SerializationException>(() => XPathQueryGenerator.CreateFromDataContractSerializer(typeof(RootDerived), new MemberInfo[] { Field<RootDerived>(nameof(RootDerived.Unmarked)) }, out _));
            Assert.Throws<SerializationException>(() => XPathQueryGenerator.CreateFromDataContractSerializer(typeof(RootDerived), new MemberInfo[] { Field<Foreign>(nameof(Foreign.Id)) }, out _));
            Assert.Throws<SerializationException>(() => XPathQueryGenerator.CreateFromDataContractSerializer(typeof(RootDerived), new MemberInfo[] { Field<RootBase>(nameof(RootBase.Id)), Field<RootMiddle>(nameof(RootMiddle.Code)) }, out _));
            Assert.Throws<ArgumentNullException>(() => XPathQueryGenerator.CreateFromDataContractSerializer(null!, Array.Empty<MemberInfo>(), out _));
            Assert.Throws<ArgumentNullException>(() => XPathQueryGenerator.CreateFromDataContractSerializer(typeof(RootDerived), null!, out _));
        }

        [DataContract(Name = "Base", Namespace = BaseNamespace)]
        public class RootBase
        {
            [DataMember(Name = "id")] public int Id;
            [DataMember(Name = "nested")] public NestedDerived? Child;
            [DataMember(Name = "caption")] public virtual string? Caption { get; set; }
        }
        [DataContract(Name = "Middle", Namespace = MiddleNamespace)]
        public class RootMiddle : RootBase { [DataMember(Name = "code")] public string? Code; }
        [DataContract(Name = "Derived", Namespace = RootNamespace)]
        public sealed class RootDerived : RootMiddle
        {
            [DataMember(Name = "own name")] public string? Own;
            public string? Unmarked = null;
            public override string? Caption
            {
                get => base.Caption is null ? null : base.Caption + "-override";
                set => base.Caption = value;
            }
        }
        [DataContract(Name = "NestedBase", Namespace = LeafNamespace)]
        public class NestedBase { [DataMember(Name = "value")] public string? Value; }
        [DataContract(Name = "NestedDerived", Namespace = "urn:xpath-leaf")]
        public sealed class NestedDerived : NestedBase { }
        [DataContract(Name = "SameBase", Namespace = "urn:xpath-same")]
        public class SameBase { [DataMember(Name = "id")] public int Id; }
        [DataContract(Name = "SameDerived", Namespace = "urn:xpath-same")]
        public sealed class SameDerived : SameBase { }
        public sealed class Foreign { public int Id = 0; }
    }
}
