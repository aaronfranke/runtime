//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//
// ============================================================================
// File: stackwalktypes.h
//

// ============================================================================
// Contains types used by stackwalk.h.


#ifndef __STACKWALKTYPES_H__
#define __STACKWALKTYPES_H__

class CrawlFrame;
struct RangeSection;
struct StackwalkCacheEntry;

//
// This type should be used internally inside the code manager only. EECodeInfo should 
// be used in general code instead. Ideally, we would replace all uses of METHODTOKEN 
// with EECodeInfo.
//
struct METHODTOKEN
{
    METHODTOKEN(RangeSection * pRangeSection, TADDR pCodeHeader)
        : m_pRangeSection(pRangeSection), m_pCodeHeader(pCodeHeader)
    {
    }

    METHODTOKEN()
    {
    }

    // Cache of RangeSection containing the code to avoid redundant lookups.
    RangeSection * m_pRangeSection;

    // CodeHeader* for EEJitManager
    // PTR_RUNTIME_FUNCTION for managed native code
    TADDR m_pCodeHeader;

    BOOL IsNull() const
    {
        return m_pCodeHeader == NULL;
    }
};

//************************************************************************
// Stack walking
//************************************************************************
enum StackCrawlMark
{
    LookForMe = 0,
    LookForMyCaller = 1,
    LookForMyCallersCaller = 2,
    LookForThread = 3
};

enum StackWalkAction 
{
    SWA_CONTINUE    = 0,    // continue walking
    SWA_ABORT       = 1,    // stop walking, early out in "failure case"
    SWA_FAILED      = 2     // couldn't walk stack
};

#define SWA_DONE SWA_CONTINUE


// Pointer to the StackWalk callback function.
typedef StackWalkAction (*PSTACKWALKFRAMESCALLBACK)(
    CrawlFrame       *pCF,      //
    VOID*             pData     // Caller's private data

);

/******************************************************************************
   StackwalkCache: new class implements stackwalk perf optimization features.
   StackwalkCacheEntry array: very simple per thread hash table, keeping cached data.
   StackwalkCacheUnwindInfo: used by EECodeManager::UnwindStackFrame to return
   stackwalk cache flags.
   Cf. Ilyakoz for any questions.
*/

struct StackwalkCacheUnwindInfo
{
#if defined(_TARGET_AMD64_)
    ULONG RBPOffset;
    ULONG RSPOffsetFromUnwindInfo;
#else  // !_TARGET_AMD64_
    size_t securityObjectOffset;    // offset of SecurityObject. 0 if there is no security object
    BOOL fUseEbp;                   // Is EBP modified by the method - either for a frame-pointer or for a scratch-register?
    BOOL fUseEbpAsFrameReg;         // use EBP as the frame pointer?
#endif // !_TARGET_AMD64_

    inline StackwalkCacheUnwindInfo() { SUPPORTS_DAC; ZeroMemory(this, sizeof(StackwalkCacheUnwindInfo)); }
    StackwalkCacheUnwindInfo(StackwalkCacheEntry * pCacheEntry);
};

//************************************************************************

#if defined(_WIN64)
    #define STACKWALK_CACHE_ENTRY_ALIGN_BOUNDARY 0x10
#else  // !_WIN64
    #define STACKWALK_CACHE_ENTRY_ALIGN_BOUNDARY 0x8
#endif // !_WIN64

DECLSPEC_ALIGN(STACKWALK_CACHE_ENTRY_ALIGN_BOUNDARY) 
struct StackwalkCacheEntry
{
    //
    //  don't rearrange the fields, so that invalid value 0x8000000000000000 will never appear
    //  as StackwalkCacheEntry, it's required for atomicMOVQ using FILD/FISTP instructions
    //
    UINT_PTR IP;
#if !defined(_TARGET_AMD64_)
    WORD ESPOffset:15;          // stack offset (frame size + pending arguments + etc)
    WORD securityObjectOffset:3;// offset of SecurityObject. 0 if there is no security object
    WORD fUseEbp:1;             // For ESP methods, is EBP touched at all?
    WORD fUseEbpAsFrameReg:1;   // use EBP as the frame register?
    WORD argSize:11;            // size of args pushed on stack
#else  // _TARGET_AMD64_
    DWORD RSPOffset;
    DWORD RBPOffset;
#endif // _TARGET_AMD64_

    inline BOOL Init(UINT_PTR   IP,
                     UINT_PTR   SPOffset,
                     StackwalkCacheUnwindInfo *pUnwindInfo,
                     UINT_PTR   argSize)
    {
        LIMITED_METHOD_CONTRACT;

        this->IP              = IP;

#if defined(_TARGET_X86_)
        this->ESPOffset         = SPOffset;
        this->argSize           = argSize;
        
        this->securityObjectOffset = (WORD)pUnwindInfo->securityObjectOffset;
        _ASSERTE(this->securityObjectOffset == pUnwindInfo->securityObjectOffset);
        
        this->fUseEbp           = pUnwindInfo->fUseEbp;
        this->fUseEbpAsFrameReg = pUnwindInfo->fUseEbpAsFrameReg;
        _ASSERTE(!fUseEbpAsFrameReg || fUseEbp);

        // return success if we fit SPOffset and argSize into
        return ((this->ESPOffset == SPOffset) && 
                (this->argSize == argSize));
#elif defined(_TARGET_AMD64_)
        // The size of a stack frame is guaranteed to fit in 4 bytes, so we don't need to check RSPOffset and RBPOffset.

        // The actual SP offset may be bigger than the offset we get from the unwind info because of stack allocations.
        _ASSERTE(SPOffset >= pUnwindInfo->RSPOffsetFromUnwindInfo);

        _ASSERTE(FitsIn<DWORD>(SPOffset));
        this->RSPOffset  = static_cast<DWORD>(SPOffset);
        _ASSERTE(FitsIn<DWORD>(pUnwindInfo->RBPOffset + (SPOffset - pUnwindInfo->RSPOffsetFromUnwindInfo)));
        this->RBPOffset  = static_cast<DWORD>(pUnwindInfo->RBPOffset + (SPOffset - pUnwindInfo->RSPOffsetFromUnwindInfo));
        return TRUE;
#else  // !_TARGET_X86_ && !_TARGET_AMD64_
        return FALSE;
#endif // !_TARGET_X86_ && !_TARGET_AMD64_
    }

    inline BOOL HasSecurityObject()
    {
        LIMITED_METHOD_CONTRACT;

#if defined(_TARGET_X86_)
        return securityObjectOffset != 0;
#else  // !_TARGET_X86_
        // On AMD64 we don't save anything by grabbing the security object before it is needed.  This is because
        // we need to crack the GC info in order to find the security object, and to unwind we only need to
        // crack the unwind info.
        return FALSE;
#endif // !_TARGET_X86_
    }

    inline BOOL IsSafeToUseCache()
    {
        LIMITED_METHOD_CONTRACT;

#if defined(_TARGET_X86_)
        return (!fUseEbp || fUseEbpAsFrameReg);
#elif defined(_TARGET_AMD64_)
        return TRUE;
#else  // !_TARGET_X86_ && !_TARGET_AMD64_
        return FALSE;
#endif // !_TARGET_X86_ && !_TARGET_AMD64_
    }
};

#if defined(_TARGET_X86_) || defined(_TARGET_AMD64_)
static_assert_no_msg(sizeof(StackwalkCacheEntry) == 2 * sizeof(UINT_PTR));
#endif // _TARGET_X86_ || _TARGET_AMD64_

//************************************************************************

class StackwalkCache 
{
    friend struct _DacGlobals;

    public:
        BOOL Lookup(UINT_PTR IP);
        void Insert(StackwalkCacheEntry *pCacheEntry);
        inline void ClearEntry () { LIMITED_METHOD_DAC_CONTRACT; m_CacheEntry.IP = 0; }
        inline BOOL Enabled() { LIMITED_METHOD_DAC_CONTRACT;  return s_Enabled; };
        inline BOOL IsEmpty () { LIMITED_METHOD_CONTRACT;  return m_CacheEntry.IP == 0; }

#ifndef DACCESS_COMPILE
        StackwalkCache();
#endif
        static void Init();

        StackwalkCacheEntry m_CacheEntry; // local copy of Global Cache entry for current IP
        
        static void Invalidate(LoaderAllocator * pLoaderAllocator);
        
    private:
        unsigned GetKey(UINT_PTR IP);
        
#ifdef DACCESS_COMPILE
        // DAC can't rely on the cache here
        const static BOOL s_Enabled;
#else
        static BOOL s_Enabled;
#endif
};

//************************************************************************

inline StackwalkCacheUnwindInfo::StackwalkCacheUnwindInfo(StackwalkCacheEntry * pCacheEntry) 
{
    LIMITED_METHOD_CONTRACT;
    
#if defined(_TARGET_AMD64_)
    RBPOffset = pCacheEntry->RBPOffset;
#else  // !_TARGET_AMD64_
    securityObjectOffset = pCacheEntry->securityObjectOffset;
    fUseEbp = pCacheEntry->fUseEbp;
    fUseEbpAsFrameReg = pCacheEntry->fUseEbpAsFrameReg;
#endif // !_TARGET_AMD64_
}

#endif  // __STACKWALKTYPES_H__
