// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.IO;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Microsoft.Extensions.Logging.Console.Test
{
    public class ConsoleLoggerBufferRecoveryTests
    {
        [ConditionalTheory(typeof(PlatformDetection), nameof(PlatformDetection.IsMultithreadingSupported))]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void FormatterThrows_ClearsSharedBuffer(bool failedBatch, bool nextBatch)
        {
            var console = new CollectingConsole();
            using var processor = new ConsoleLoggerProcessor(console, console, ConsoleLoggerQueueFullMode.Wait, 32);
            var logger = new ConsoleLogger("test", processor, new ThrowingFormatter(), null, new ConsoleLoggerOptions());

            if (failedBatch)
            {
                Assert.Throws<FormatException>(() => logger.LogRecords(new[] { new Record("fail") }));
            }
            else
            {
                Assert.Throws<FormatException>(() => logger.LogInformation("fail"));
            }

            if (nextBatch)
            {
                logger.LogRecords(new[] { new Record("after") });
            }
            else
            {
                logger.LogInformation("after");
            }

            processor.Dispose();
            Assert.Equal("after" + Environment.NewLine, console.Text);
        }

        private sealed class CollectingConsole : IConsole
        {
            private readonly StringBuilder _text = new StringBuilder();
            public string Text
            {
                get
                {
                    lock (_text)
                    {
                        return _text.ToString();
                    }
                }
            }
            public void Write(string message)
            {
                lock (_text)
                {
                    _text.Append(message);
                }
            }
        }

        private sealed class Record(string message) : BufferedLogRecord
        {
            public override DateTimeOffset Timestamp => default;
            public override LogLevel LogLevel => LogLevel.Information;
            public override EventId EventId => default;
            public override string FormattedMessage => message;
        }

        private sealed class ThrowingFormatter() : ConsoleFormatter("throwing")
        {
            public override void Write<TState>(in LogEntry<TState> entry, IExternalScopeProvider? scopeProvider, TextWriter writer)
            {
                string? message = entry.State is BufferedLogRecord record ? record.FormattedMessage : entry.Formatter(entry.State, entry.Exception);
                if (message == "fail")
                {
                    writer.Write("partial output");
                    throw new FormatException("formatter failure");
                }
                writer.WriteLine(message);
            }
        }
    }
}
