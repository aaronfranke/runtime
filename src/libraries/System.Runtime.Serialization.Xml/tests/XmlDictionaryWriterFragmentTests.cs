// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Xunit;

public static class XmlDictionaryWriterFragmentTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public static void TextWriter_FragmentRoundTrip(bool selfContained)
    {
        using var output = new MemoryStream();
        using var fragment = new MemoryStream();
        using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(output, Encoding.UTF8, false);
        var fragments = Assert.IsAssignableFrom<IFragmentCapableXmlDictionaryWriter>(writer);
        Assert.True(fragments.CanFragment);
        writer.WriteStartElement("p", "root", "urn:p");
        fragments.StartFragment(fragment, selfContained);
        writer.WriteElementString("p", "item", "urn:p", "value");
        fragments.EndFragment();
        byte[] bytes = fragment.ToArray();
        fragments.WriteFragment(bytes, 0, bytes.Length);
        writer.WriteEndElement();
        writer.Flush();
        var document = new XmlDocument();
        document.LoadXml(Encoding.UTF8.GetString(output.ToArray()));
        Assert.Equal("value", document.DocumentElement!.FirstChild!.InnerText);
        Assert.Equal("urn:p", document.DocumentElement!.FirstChild!.NamespaceURI);
        if (selfContained)
        {
            document.LoadXml(Encoding.UTF8.GetString(bytes));
            Assert.Equal("urn:p", document.DocumentElement!.NamespaceURI);
        }
        Assert.True(fragment.CanWrite);
    }

    [Fact]
    public static void TextWriter_Utf16CannotFragment()
    {
        using var output = new MemoryStream();
        using var fragment = new MemoryStream();
        using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(output, Encoding.Unicode, false);
        var fragments = Assert.IsAssignableFrom<IFragmentCapableXmlDictionaryWriter>(writer);
        Assert.False(fragments.CanFragment);
        Assert.Throws<NotSupportedException>(() => fragments.StartFragment(fragment, true));
        Assert.Throws<NotSupportedException>(() => fragments.WriteFragment(Array.Empty<byte>(), 0, 0));
        Assert.Throws<InvalidOperationException>(() => fragments.EndFragment());
    }

    [Fact]
    public static async Task TextWriter_FragmentOperationsRespectPendingAsyncWrite()
    {
        using var output = new GatedStream();
        using var fragment = new MemoryStream();
        using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(output, Encoding.UTF8, false);
        var fragments = Assert.IsAssignableFrom<IFragmentCapableXmlDictionaryWriter>(writer);
        writer.WriteElementString("r", "value");
        Task pending = writer.FlushAsync();
        try
        {
            Assert.False(pending.IsCompleted);
            Assert.Throws<InvalidOperationException>(() => _ = fragments.CanFragment);
            Assert.Throws<InvalidOperationException>(() => fragments.StartFragment(fragment, true));
            Assert.Throws<InvalidOperationException>(() => fragments.EndFragment());
            Assert.Throws<InvalidOperationException>(() => fragments.WriteFragment(Array.Empty<byte>(), 0, 0));
        }
        finally
        {
            output.Release();
            await pending;
        }
        Assert.True(fragments.CanFragment);
        Assert.Equal("<r>value</r>", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public static void BinaryWriter_FragmentCapabilityIsPreserved()
    {
        using var output = new MemoryStream();
        using var fragment = new MemoryStream();
        using XmlDictionaryWriter writer = XmlDictionaryWriter.CreateBinaryWriter(output, null, null, false);
        var fragments = Assert.IsAssignableFrom<IFragmentCapableXmlDictionaryWriter>(writer);
        Assert.True(fragments.CanFragment);
        writer.WriteStartElement("r");
        fragments.StartFragment(fragment, true);
        writer.WriteElementString("item", "value");
        fragments.EndFragment();
        writer.WriteEndElement();
        writer.Flush();
        var document = new XmlDocument();
        document.LoadXml(Encoding.UTF8.GetString(fragment.ToArray()));
        Assert.Equal("value", document.DocumentElement!.InnerText);
    }

    private sealed class GatedStream : MemoryStream
    {
        private readonly TaskCompletionSource<bool> _gate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Release() => _gate.TrySetResult(true);
        private async Task WriteAfterRelease(ReadOnlyMemory<byte> buffer)
        {
            await _gate.Task;
            base.Write(buffer.Span);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAfterRelease(buffer.AsMemory(offset, count));
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => new(WriteAfterRelease(buffer));
    }
}
