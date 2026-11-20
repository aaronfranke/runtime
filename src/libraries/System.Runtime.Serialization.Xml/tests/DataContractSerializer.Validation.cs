// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Xunit;

public static partial class DataContractSerializerTests
{
    private const string ValidationNamespace = "urn:serializer-validation";

    private static T ValidationRead<T>(string members)
    {
        using var reader = XmlReader.Create(new StringReader(
            $"<Model xmlns='{ValidationNamespace}'>{members}</Model>"));
        return (T)new DataContractSerializer(typeof(T)).ReadObject(reader)!;
    }

    private static string ValidationWrite<T>(T value, bool serializeReadOnlyTypes = false)
    {
        var text = new StringBuilder();
        using (var writer = XmlWriter.Create(text, new XmlWriterSettings { OmitXmlDeclaration = true }))
        {
            new DataContractSerializer(typeof(T), new DataContractSerializerSettings
            {
                SerializeReadOnlyTypes = serializeReadOnlyTypes
            }).WriteObject(writer, value);
        }
        return text.ToString();
    }

    [Fact]
    public static void DCS_RequiredMembers_MissingAtEnd_Throws()
    {
        Assert.Throws<SerializationException>(() => ValidationRead<ValidationDerived>(""));
        Assert.Throws<SerializationException>(() => ValidationRead<ValidationDerived>("<OptionalBefore>1</OptionalBefore>"));
        Assert.Throws<SerializationException>(() => ValidationRead<ValidationDerived>(
            "<RequiredBase>2</RequiredBase><OptionalMiddle>3</OptionalMiddle>"));
    }

    [Fact]
    public static void DCS_RequiredMembers_MissingBeforeLaterMember_Throws()
    {
        Assert.Throws<SerializationException>(() => ValidationRead<ValidationDerived>("<OptionalMiddle>3</OptionalMiddle>"));
        Assert.Throws<SerializationException>(() => ValidationRead<ValidationDerived>(
            "<RequiredBase>2</RequiredBase><OptionalAfter>5</OptionalAfter>"));
    }

    [Fact]
    public static void DCS_RequiredMembers_OptionalMembersMayBeOmitted()
    {
        ValidationDerived result = ValidationRead<ValidationDerived>("<RequiredBase>2</RequiredBase><RequiredLast>4</RequiredLast>");
        Assert.Equal(2, result.RequiredBase);
        Assert.Equal(4, result.RequiredLast);
        Assert.Equal(0, result.OptionalBefore);
        Assert.Equal(0, result.OptionalMiddle);
        Assert.Equal(0, result.OptionalAfter);
    }

    [Fact]
    public static void DCS_RequiredMembers_UnknownMembersPreserveProgress()
    {
        ValidationDerived result = ValidationRead<ValidationDerived>(
            "<Unknown>a</Unknown><RequiredBase>2</RequiredBase><Unknown>b</Unknown><RequiredLast>4</RequiredLast><Unknown>c</Unknown>");
        Assert.Equal(2, result.RequiredBase);
        Assert.Equal(4, result.RequiredLast);
        Assert.NotNull(result.ExtensionData);
        Assert.Equal(new[] { "a", "b", "c" }, XDocument.Parse(ValidationWrite(result))
            .Descendants(XName.Get("Unknown", ValidationNamespace)).Select(element => element.Value));
    }

    [Fact]
    public static void DCS_UnknownMembers_DoNotDiscardLaterKnownMembers()
    {
        ValidationOptional result = ValidationRead<ValidationOptional>(
            "<Unknown>a</Unknown><First>2</First><Unknown>b</Unknown><Last>4</Last>");
        Assert.Equal(2, result.First);
        Assert.Equal(4, result.Last);
    }

    [Fact]
    public static void DCS_GetterOnlyMember_RequiresOptInBeforeCallbacks()
    {
        var value = new ValidationReadOnly();
        Assert.Throws<InvalidDataContractException>(() => ValidationWrite(value));
        Assert.Equal(0, value.CallbackCalls);
    }

    [Fact]
    public static void DCS_GetterOnlyMember_OptInAllowsWriteButNotRead()
    {
        var value = new ValidationReadOnly();
        string xml = ValidationWrite(value, serializeReadOnlyTypes: true);
        Assert.Equal("42", XDocument.Parse(xml).Root!.Element(XName.Get("Value", ValidationNamespace))!.Value);
        Assert.Equal(1, value.CallbackCalls);
        using var reader = XmlReader.Create(new StringReader(xml));
        Assert.Throws<InvalidDataContractException>(() => new DataContractSerializer(typeof(ValidationReadOnly)).ReadObject(reader));
    }

    [DataContract(Namespace = ValidationNamespace)]
    public class ValidationBase : IExtensibleDataObject
    {
        [DataMember(Order = 0)] public int OptionalBefore = 0;
        [DataMember(Order = 1, IsRequired = true)] public int RequiredBase = 0;
        public ExtensionDataObject? ExtensionData { get; set; }
    }

    [DataContract(Name = "Model", Namespace = ValidationNamespace)]
    public class ValidationDerived : ValidationBase
    {
        [DataMember(Order = 0)] public int OptionalMiddle = 0;
        [DataMember(Order = 1, IsRequired = true)] public int RequiredLast = 0;
        [DataMember(Order = 2)] public int OptionalAfter = 0;
    }

    [DataContract(Name = "Model", Namespace = ValidationNamespace)]
    public class ValidationOptional
    {
        [DataMember(Order = 0)] public int First = 0;
        [DataMember(Order = 1)] public int Last = 0;
    }

    [DataContract(Name = "Model", Namespace = ValidationNamespace)]
    public class ValidationReadOnly
    {
        public int CallbackCalls;
        [DataMember] public int Value => 42;
        [OnSerializing]
        public void OnSerializing(StreamingContext context)
        {
            CallbackCalls++;
        }
    }
}
