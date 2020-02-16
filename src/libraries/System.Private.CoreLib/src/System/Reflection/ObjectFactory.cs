// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.CompilerServices;
using Internal.Runtime.CompilerServices;

namespace System.Reflection
{
    public sealed class ObjectFactory<T> : IObjectFactory where T : class, new()
    {
        private readonly IntPtr _typeHnd;
        private readonly IntPtr _newobjFn;
        private readonly IntPtr _ctorFn;

        public ObjectFactory()
        {
            // TODO: Make sure T isn't array or string
            // TODO: Special-case reference type T vs. value type T

            RuntimeType rt = typeof(T) as RuntimeType ?? throw new NotSupportedException();

            RuntimeHelpers.RunClassConstructor(rt.GetTypeHandleInternal());
            _typeHnd = rt.GetTypeHandleInternal().Value;
            _newobjFn = RuntimeHelpers.GetNewobjHelper(typeof(T));
            _ctorFn = typeof(T).GetConstructor(Type.EmptyTypes)!.MethodHandle.GetFunctionPointer();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public T CreateObject()
        {
            T retVal = Unsafe.As<T>(RuntimeHelpers.InvokeNewobjHelper(_typeHnd, _newobjFn));

            if (!typeof(T).IsValueType)
            {
                // call parameterless ctor
                RuntimeHelpers.InvokeCtor(retVal, _ctorFn);
            }

            GC.KeepAlive(this); // keeps 'T' instantiation alive
            return retVal;
        }

        object? IObjectFactory.CreateObject()
        {
            object retVal = RuntimeHelpers.InvokeNewobjHelper(_typeHnd, _newobjFn);

            if (!typeof(T).IsValueType)
            {
                // call parameterless ctor
                RuntimeHelpers.InvokeCtor(retVal, _ctorFn);
            }

            GC.KeepAlive(this); // keeps 'T' instantiation alive
            return retVal;
        }
    }

    public interface IObjectFactory
    {
        object? CreateObject();
    }
}
