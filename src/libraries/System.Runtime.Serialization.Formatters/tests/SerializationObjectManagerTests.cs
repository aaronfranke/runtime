// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace System.Runtime.Serialization.Formatters.Tests
{
    public class SerializationObjectManagerTests
    {
        [Fact]
        public void RegisterObject_SameObjectTwice_InvokesCallbacksOnce()
        {
            var marker = new object();
            var manager = new SerializationObjectManager(new StreamingContext(StreamingContextStates.All, marker));
            var target = new CallbackTarget(7);

            manager.RegisterObject(target);
            manager.RegisterObject(target);

            Assert.Equal(1, target.SerializingCount);
            Assert.Equal(0, target.SerializedCount);
            manager.RaiseOnSerializedEvent();
            Assert.Equal(1, target.SerializedCount);
            Assert.Same(marker, target.SerializingContext);
            Assert.Same(marker, target.SerializedContext);
        }

        [Fact]
        public void RegisterObject_DistinctEqualObjects_InvokesCallbacksForBoth()
        {
            var manager = new SerializationObjectManager(default);
            var first = new CallbackTarget(7);
            var second = new CallbackTarget(7);

            manager.RegisterObject(first);
            manager.RegisterObject(second);
            manager.RaiseOnSerializedEvent();

            Assert.Equal(1, first.SerializingCount);
            Assert.Equal(1, second.SerializingCount);
            Assert.Equal(1, first.SerializedCount);
            Assert.Equal(1, second.SerializedCount);
        }

        [Fact]
        public void RegisterObject_HashCodeChangesInCallback_InvokesCallbacksOnce()
        {
            var manager = new SerializationObjectManager(default);
            var target = new CallbackTarget(7) { ChangeValueInCallback = true };

            manager.RegisterObject(target);
            manager.RegisterObject(target);
            manager.RaiseOnSerializedEvent();

            Assert.Equal(8, target.Value);
            Assert.Equal(1, target.SerializingCount);
            Assert.Equal(1, target.SerializedCount);
        }

        [Fact]
        public void RegisterObject_DoesNotCallUserEqualityMembers()
        {
            var manager = new SerializationObjectManager(default);
            var target = new CallbackTarget(7) { ThrowIfEqualityIsUsed = true };

            manager.RegisterObject(target);
            manager.RaiseOnSerializedEvent();

            Assert.Equal(1, target.SerializingCount);
            Assert.Equal(1, target.SerializedCount);
        }

        private sealed class CallbackTarget
        {
            // Callback discovery reflects over this exact model in trimmed/AOT test runs.
            [DynamicDependency(DynamicallyAccessedMemberTypes.PublicMethods, typeof(CallbackTarget))]
            public CallbackTarget(int value) => Value = value;
            public int Value { get; private set; }
            public bool ChangeValueInCallback { get; set; }
            public bool ThrowIfEqualityIsUsed { get; set; }
            public int SerializingCount { get; private set; }
            public int SerializedCount { get; private set; }
            public object? SerializingContext { get; private set; }
            public object? SerializedContext { get; private set; }

            [OnSerializing]
            public void OnSerializing(StreamingContext context)
            {
                SerializingCount++;
                SerializingContext = context.Context;
                if (ChangeValueInCallback)
                {
                    Value++;
                }
            }

            [OnSerialized]
            public void OnSerialized(StreamingContext context)
            {
                SerializedCount++;
                SerializedContext = context.Context;
            }

            public override bool Equals(object? other)
            {
                if (ThrowIfEqualityIsUsed)
                {
                    throw new InvalidOperationException("User equality must not determine callback registration.");
                }
                return other is CallbackTarget target && Value == target.Value;
            }

            public override int GetHashCode()
            {
                if (ThrowIfEqualityIsUsed)
                {
                    throw new InvalidOperationException("User hashing must not determine callback registration.");
                }
                return Value;
            }
        }
    }
}
