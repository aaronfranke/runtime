// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using Xunit;

namespace System.Reflection.Emit.Tests
{
    public class TypeLayoutPersistenceTests
    {
        [Theory]
        [InlineData(TypeAttributes.SequentialLayout, PackingSize.Size1, 5)]
        [InlineData(TypeAttributes.SequentialLayout, PackingSize.Size2, 6)]
        [InlineData(TypeAttributes.SequentialLayout, PackingSize.Unspecified, 12)]
        [InlineData(TypeAttributes.SequentialLayout, PackingSize.Unspecified, 0)]
        [InlineData(TypeAttributes.ExplicitLayout, PackingSize.Size1, 5)]
        [InlineData(TypeAttributes.ExplicitLayout, PackingSize.Unspecified, 0)]
        [InlineData(TypeAttributes.AutoLayout, PackingSize.Unspecified, 0)]
        public void Layout_RoundTrips(TypeAttributes layoutKind, PackingSize packing, int size)
        {
            var assembly = new PersistedAssemblyBuilder(new AssemblyName("LayoutModel"), typeof(object).Assembly);
            ModuleBuilder module = assembly.DefineDynamicModule("LayoutModel");
            TypeBuilder type = module.DefineType("Sample", TypeAttributes.Public | TypeAttributes.Sealed | layoutKind,
                typeof(ValueType), packing, size);
            FieldBuilder first = type.DefineField("First", typeof(byte), FieldAttributes.Public);
            FieldBuilder second = type.DefineField("Second", typeof(int), FieldAttributes.Public);
            if (layoutKind == TypeAttributes.ExplicitLayout)
            {
                first.SetOffset(0);
                second.SetOffset(1);
            }
            type.CreateTypeInfo();

            using var stream = new MemoryStream();
            assembly.Save(stream);
            stream.Position = 0;
            using var pe = new PEReader(stream);
            MetadataReader reader = pe.GetMetadataReader();
            TypeDefinition definition = reader.TypeDefinitions.Select(reader.GetTypeDefinition)
                .Single(t => reader.GetString(t.Name) == "Sample");
            TypeLayout layout = definition.GetLayout();
            Assert.Equal(layoutKind, definition.Attributes & TypeAttributes.LayoutMask);
            if (layoutKind == TypeAttributes.AutoLayout || (layoutKind == TypeAttributes.SequentialLayout && packing == PackingSize.Unspecified && size == 0))
            {
                // IsDefault alone cannot distinguish an absent row from a (0, 0) row.
                Assert.Equal(0, reader.GetTableRowCount(TableIndex.ClassLayout));
                Assert.True(layout.IsDefault);
            }
            else
            {
                Assert.Equal(1, reader.GetTableRowCount(TableIndex.ClassLayout));
                Assert.Equal((int)packing, layout.PackingSize);
                Assert.Equal(size, layout.Size);
            }
        }
    }
}
