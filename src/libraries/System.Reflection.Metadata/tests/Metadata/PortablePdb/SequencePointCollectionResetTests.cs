// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using Xunit;

namespace System.Reflection.Metadata.Tests
{
    public class SequencePointCollectionResetTests
    {
        [Theory]
        [InlineData(true, 0)]
        [InlineData(true, 1)]
        [InlineData(true, 2)]
        [InlineData(true, 4)]
        [InlineData(false, 0)]
        [InlineData(false, 1)]
        [InlineData(false, 2)]
        [InlineData(false, 4)]
        public void Reset_RestoresOriginalDocumentAndPosition(bool fixedDocument, int advances)
        {
            var metadata = new MetadataBuilder();
            DocumentHandle first = metadata.AddDocument(metadata.GetOrAddDocumentName("one.cs"), default, default, default);
            metadata.AddDocument(metadata.GetOrAddDocumentName("two.cs"), default, default, default);
            var points = new BlobBuilder();
            points.WriteCompressedInteger(0);
            if (!fixedDocument)
            {
                points.WriteCompressedInteger(1);
            }
            foreach (int value in new[] { 0, 0, 5, 10, 1, 2, 0, 0, 0, 2, 3, 1 })
            {
                points.WriteCompressedInteger(value);
            }
            points.WriteCompressedSignedInteger(4);
            points.WriteCompressedSignedInteger(10);
            points.WriteCompressedSignedInteger(2);
            metadata.AddMethodDebugInformation(fixedDocument ? first : default, metadata.GetOrAddBlob(points));
            var rowCounts = new int[MetadataTokens.TableCount];
            rowCounts[(int)TableIndex.MethodDef] = 1;
            var bytes = new BlobBuilder();
            new PortablePdbBuilder(metadata, ImmutableArray.Create(rowCounts), default,
                _ => new BlobContentId(new Guid("4e1614dd-d85e-4417-9c07-641091f8a541"), 1)).Serialize(bytes);
            using var provider = MetadataReaderProvider.FromPortablePdbImage(bytes.ToImmutableArray());
            SequencePointCollection collection = provider.GetMetadataReader().GetMethodDebugInformation(MetadataTokens.MethodDefinitionHandle(1)).GetSequencePoints();
            string[] expected = { "1:0:10,1-10,6", "1:2:hidden", "2:5:20,3-21,7" };
            Assert.Equal(expected, collection.Select(Describe));
            SequencePointCollection.Enumerator cursor = collection.GetEnumerator();
            for (int i = 0; i < advances; i++)
            {
                cursor.MoveNext();
            }
            for (int repeat = 0; repeat < 2; repeat++)
            {
                cursor.Reset();
                var actual = new List<string>();
                while (cursor.MoveNext())
                {
                    actual.Add(Describe(cursor.Current));
                }
                Assert.Equal(expected, actual);
            }
        }

        private static string Describe(SequencePoint point) => point.IsHidden
            ? $"{MetadataTokens.GetRowNumber(point.Document)}:{point.Offset}:hidden"
            : $"{MetadataTokens.GetRowNumber(point.Document)}:{point.Offset}:{point.StartLine},{point.StartColumn}-{point.EndLine},{point.EndColumn}";
    }
}
