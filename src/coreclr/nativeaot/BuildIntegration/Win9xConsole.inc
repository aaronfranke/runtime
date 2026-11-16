// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/* Win9x console output translation for the CSI sequences used by PrettyPrompt. */

enum terminal_input {
    TERMINAL_TEXT,
    TERMINAL_ESCAPE,
    TERMINAL_CSI,
    TERMINAL_IGNORE_CSI
};

static struct {
    HANDLE handle;
    DWORD modes;
    WORD initial_attributes;
    enum terminal_input input;
    unsigned count;
    unsigned values[16];
} terminal;

static volatile LONG terminal_lock;

static void lock_terminal(void)
{
    while (InterlockedExchange(&terminal_lock, 1)) {
        Sleep(0);
    }
}

static void unlock_terminal(void)
{
    InterlockedExchange(&terminal_lock, 0);
}

THUNK(BOOL, GetConsoleMode, 8, (HANDLE handle, DWORD *mode))
{
    typedef BOOL (WINAPI *get_mode_fn)(HANDLE, DWORD *);
    get_mode_fn native = (get_mode_fn)kernel_proc("GetConsoleMode");
    BOOL result = native(handle, mode);
    if (result && is_win9x()) {
        lock_terminal();
        if (terminal.handle == handle) {
            *mode |= terminal.modes;
        }
        unlock_terminal();
    }
    return result;
}

THUNK(BOOL, SetConsoleMode, 8, (HANDLE handle, DWORD mode))
{
    typedef BOOL (WINAPI *set_mode_fn)(HANDLE, DWORD);
    set_mode_fn native = (set_mode_fn)kernel_proc("SetConsoleMode");

    if (!is_win9x()) {
        return native(handle, mode);
    }

    lock_terminal();
    if (handle != GetStdHandle(STD_OUTPUT_HANDLE)) {
        unlock_terminal();
        return native(handle, mode);
    }

    CONSOLE_SCREEN_BUFFER_INFO screen;
    const DWORD translated = ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    BOOL emulated = (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 &&
        (mode & ENABLE_PROCESSED_OUTPUT) != 0 &&
        GetConsoleScreenBufferInfo(handle, &screen);
    DWORD native_mode = emulated ? mode & ~translated : mode;
    BOOL result = native(handle, native_mode);
    DWORD error = GetLastError();
    if (result && emulated) {
        if (terminal.handle != handle) {
            terminal.handle = handle;
            terminal.initial_attributes = screen.wAttributes;
            terminal.input = TERMINAL_TEXT;
        }
        terminal.modes = mode & translated;
    } else if (result && terminal.handle == handle) {
        terminal.handle = NULL;
        terminal.modes = 0;
        terminal.input = TERMINAL_TEXT;
    }
    unlock_terminal();
    SetLastError(error);
    return result;
}

static unsigned shade(unsigned r, unsigned g, unsigned b)
{
    unsigned best = 0;
    unsigned distance = UINT_MAX;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned level = i < 8 ? 128 : 255;
        unsigned low = i < 8 ? 0 : 128;
        unsigned ri = i == 7 ? 192 : i == 8 ? 128 : i & 4 ? level : low;
        unsigned gi = i == 7 ? 192 : i == 8 ? 128 : i & 2 ? level : low;
        unsigned bi = i == 7 ? 192 : i == 8 ? 128 : i & 1 ? level : low;
        if (i > 8) {
            ri = i & 4 ? 255 : 0;
            gi = i & 2 ? 255 : 0;
            bi = i & 1 ? 255 : 0;
        }
        int dr = (int)r - (int)ri, dg = (int)g - (int)gi, db = (int)b - (int)bi;
        unsigned score = (unsigned)(dr * dr + dg * dg + db * db);
        if (score < distance) {
            best = i;
            distance = score;
        }
    }
    return best;
}

static unsigned ansi_color(unsigned ansi)
{
    return (ansi & 10) | (ansi & 1) << 2 | (ansi & 4) >> 2;
}

static BOOL apply_attributes(HANDLE handle, WORD attributes)
{
    for (unsigned i = 0; i < terminal.count; ++i) {
        unsigned code = terminal.values[i];
        if (code == 0) {
            attributes = terminal.initial_attributes;
        }
        else if (code == 1) {
            attributes |= FOREGROUND_INTENSITY;
        }
        else if (code == 22) {
            attributes &= ~FOREGROUND_INTENSITY;
        }
        else if (code == 7 || code == 27) {
            attributes = (WORD)((attributes & ~0xff) | (attributes & 0x0f) << 4 | (attributes & 0xf0) >> 4);
        }
        else if (code == 39) {
            attributes = (WORD)((attributes & ~0x0f) | (terminal.initial_attributes & 0x0f));
        }
        else if (code == 49) {
            attributes = (WORD)((attributes & ~0xf0) | (terminal.initial_attributes & 0xf0));
        }
        else if (code == 38 || code == 48) {
            if (++i == terminal.count || terminal.values[i] != 2 || terminal.count - i < 4) {
                break;
            }
            unsigned r = terminal.values[++i], g = terminal.values[++i], b = terminal.values[++i];
            if (r > 255 || g > 255 || b > 255) {
                continue;
            }
            unsigned color = ansi_color(shade(r, g, b));
            if (code == 38) {
                attributes = (WORD)((attributes & ~0x0f) | color);
            }
            else {
                attributes = (WORD)((attributes & ~0xf0) | color << 4);
            }
        } else if (code >= 30 && code <= 37) {
            attributes = (WORD)((attributes & ~0x0f) | ansi_color(code - 30));
        } else if (code >= 40 && code <= 47) {
            attributes = (WORD)((attributes & ~0xf0) | ansi_color(code - 40) << 4);
        } else if (code >= 90 && code <= 97) {
            attributes = (WORD)((attributes & ~0x0f) | ansi_color(code - 90 + 8));
        } else if (code >= 100 && code <= 107) {
            attributes = (WORD)((attributes & ~0xf0) | ansi_color(code - 100 + 8) << 4);
        }
    }
    return SetConsoleTextAttribute(handle, attributes);
}

/* Windows 95 and 98 only implement the ANSI forms of these console APIs. */
THUNK(BOOL, FillConsoleOutputCharacterW, 20, (HANDLE handle, wchar_t character, DWORD length, COORD start, DWORD *written))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *fill_character_fn)(HANDLE, wchar_t, DWORD, COORD, DWORD *);
        fill_character_fn native = (fill_character_fn)kernel_proc("FillConsoleOutputCharacterW");
        return native(handle, character, length, start, written);
    }

    UINT code_page = GetConsoleOutputCP();
    char encoded;
    BOOL replaced = FALSE;
    BOOL *used_default = code_page == CP_UTF7 || code_page == CP_UTF8 ? NULL : &replaced;
    int count = WideCharToMultiByte(code_page, 0, &character, 1, &encoded, 1, NULL, used_default);
    if (count == 0 || replaced) {
        if (replaced || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        }
        return FALSE;
    }
    return FillConsoleOutputCharacterA(handle, encoded, length, start, written);
}

THUNK(BOOL, SetConsoleTitleW, 4, (const wchar_t *title))
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *set_title_fn)(const wchar_t *);
        set_title_fn native = (set_title_fn)kernel_proc("SetConsoleTitleW");
        return native(title);
    }

    UINT code_page = GetConsoleOutputCP();
    int length = WideCharToMultiByte(code_page, 0, title, -1, NULL, 0, NULL, NULL);
    if (length == 0) {
        return FALSE;
    }

    char local[MAX_PATH];
    HANDLE heap = GetProcessHeap();
    char *ansi = length <= (int)sizeof(local) ? local : HeapAlloc(heap, 0, (SIZE_T)length);
    if (ansi == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    BOOL replaced = FALSE;
    BOOL *used_default = code_page == CP_UTF7 || code_page == CP_UTF8 ? NULL : &replaced;
    BOOL result = FALSE;
    if (WideCharToMultiByte(code_page, 0, title, -1, ansi, length, NULL, used_default) != 0) {
        if (replaced) {
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        } else {
            result = SetConsoleTitleA(ansi);
        }
    }
    DWORD error = GetLastError();
    if (ansi != local) {
        HeapFree(heap, 0, ansi);
    }
    SetLastError(error);
    return result;
}

THUNK(DWORD, GetConsoleTitleW, 8, (wchar_t *title, DWORD capacity))
{
    if (!is_win9x()) {
        typedef DWORD (WINAPI *get_title_fn)(wchar_t *, DWORD);
        get_title_fn native = (get_title_fn)kernel_proc("GetConsoleTitleW");
        return native(title, capacity);
    }

    if (title == NULL || capacity == 0 || capacity > INT_MAX) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    /* Leave room for DBCS titles up to the 64 KiB limit of the native API. */
    DWORD ansi_capacity = capacity <= 32768 ? capacity * 2 : 65536;
    char local[MAX_PATH * 2];
    HANDLE heap = GetProcessHeap();
    char *ansi = ansi_capacity <= sizeof(local) ? local : HeapAlloc(heap, 0, ansi_capacity);
    if (ansi == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    SetLastError(ERROR_SUCCESS);
    DWORD length = GetConsoleTitleA(ansi, ansi_capacity);
    DWORD error = GetLastError();
    int written = 0;
    if (length >= ansi_capacity || (length == ansi_capacity - 1 && ansi_capacity < 65536)) {
        error = ERROR_INSUFFICIENT_BUFFER;
    } else if (length != 0) {
        written = MultiByteToWideChar(GetConsoleOutputCP(), 0, ansi, (int)length, title, (int)capacity);
        if (written == 0) {
            error = GetLastError();
        } else if ((DWORD)written == capacity) {
            written = 0;
            error = ERROR_INSUFFICIENT_BUFFER;
        }
    }
    if (written != 0 || error == ERROR_SUCCESS) {
        title[written] = 0;
    }

    if (ansi != local) {
        HeapFree(heap, 0, ansi);
    }
    SetLastError(error);
    return written;
}

static BOOL clear_cells(HANDLE handle, COORD start, DWORD cells, WORD attributes)
{
    DWORD count;
    return FillConsoleOutputCharacterA(handle, ' ', cells, start, &count) &&
        FillConsoleOutputAttribute(handle, attributes, cells, start, &count);
}

static SHORT clip_coordinate(int coordinate, SHORT low, SHORT high)
{
    return coordinate < low ? low : coordinate > high ? high : (SHORT)coordinate;
}

static BOOL terminal_command(HANDLE handle, BYTE command)
{
    CONSOLE_SCREEN_BUFFER_INFO screen;
    if (!GetConsoleScreenBufferInfo(handle, &screen)) {
        return FALSE;
    }

    if (command == 'm') {
        BOOL result = apply_attributes(handle, screen.wAttributes);
        return result;
    }

    COORD cursor = screen.dwCursorPosition;
    SMALL_RECT window = screen.srWindow;
    unsigned n = terminal.values[0];
    int step = n == 0 ? 1 : (int)n;
    int x = cursor.X, y = cursor.Y;
    switch (command) {
        case 'A': y -= step; break;
        case 'B': y += step; break;
        case 'C': x += step; break;
        case 'D': x -= step; break;
        case 'G': x = window.Left + step - 1; break;
        case 'J':
            if (n == 0 || n == 2) {
                SHORT row = n == 2 ? window.Top : cursor.Y;
                SHORT col = n == 2 ? window.Left : cursor.X;
                for (; row <= window.Bottom; ++row, col = window.Left) {
                    COORD start = {col, row};
                    if (col <= window.Right && !clear_cells(handle, start, window.Right - col + 1, screen.wAttributes)) {
                        return FALSE;
                    }
                }
            }
            return TRUE;
        case 'K':
            if (n == 0) {
                return clear_cells(handle, cursor, window.Right - cursor.X + 1, screen.wAttributes);
            }
            return TRUE;
        default:
            return TRUE;
    }

    cursor.X = clip_coordinate(x, window.Left, window.Right);
    cursor.Y = clip_coordinate(y, window.Top, window.Bottom);
    return SetConsoleCursorPosition(handle, cursor);
}

static BOOL terminal_line_feed(HANDLE handle, const char *newline, DWORD *written)
{
    CONSOLE_SCREEN_BUFFER_INFO before, after;
    if (!GetConsoleScreenBufferInfo(handle, &before) ||
        !WriteConsoleA(handle, newline, 1, written, NULL) ||
        !GetConsoleScreenBufferInfo(handle, &after)) {
        return FALSE;
    }

    if (after.dwCursorPosition.X == before.dwCursorPosition.X) {
        return TRUE;
    }
    after.dwCursorPosition.X = before.dwCursorPosition.X;
    return SetConsoleCursorPosition(handle, after.dwCursorPosition);
}

static BOOL terminal_write(HANDLE handle, const char *buffer, DWORD length, DWORD *written, BOOL *handled)
{
    lock_terminal();
    if (terminal.handle != handle) {
        *handled = FALSE;
        unlock_terminal();
        return FALSE;
    }

    *handled = TRUE;
    BOOL result = TRUE;
    DWORD end = 0;
    while (end < length) {
        BYTE c = (BYTE)buffer[end];
        if (terminal.input == TERMINAL_TEXT) {
            if (c == 0x1b) {
                terminal.input = TERMINAL_ESCAPE;
                ++end;
                continue;
            }
            BOOL line_feed_only = (terminal.modes & DISABLE_NEWLINE_AUTO_RETURN) != 0;
            DWORD count = 1, consumed;
            BOOL success;
            if (line_feed_only && c == '\n') {
                success = terminal_line_feed(handle, buffer + end, &consumed);
            } else {
                while (count < length - end && buffer[end + count] != 0x1b &&
                    (!line_feed_only || buffer[end + count] != '\n')) {
                    ++count;
                }
                success = WriteConsoleA(handle, buffer + end, count, &consumed, NULL);
            }
            if (!success) {
                result = FALSE;
                break;
            }
            end += consumed;
            if (consumed != count) {
                break;
            }
            continue;
        }

        ++end;
        if (c == 0x1b) {
            terminal.input = TERMINAL_ESCAPE;
        } else if (terminal.input == TERMINAL_ESCAPE) {
            terminal.input = c == '[' ? TERMINAL_CSI : TERMINAL_TEXT;
            terminal.count = 1;
            terminal.values[0] = 0;
        } else if (c >= 0x40 && c <= 0x7e) {
            enum terminal_input state = terminal.input;
            terminal.input = TERMINAL_TEXT;
            if (state == TERMINAL_CSI && !terminal_command(handle, c)) {
                result = FALSE;
                break;
            }
        } else if (terminal.input == TERMINAL_CSI) {
            unsigned *last = &terminal.values[terminal.count - 1];
            if (c >= '0' && c <= '9' && *last <= 3276) {
                *last = *last * 10 + c - '0';
            } else if (c == ';' && terminal.count < sizeof(terminal.values) / sizeof(terminal.values[0])) {
                terminal.values[terminal.count++] = 0;
            } else {
                terminal.input = TERMINAL_IGNORE_CSI;
            }
        }
    }
    DWORD error = GetLastError();
    *written = end;
    unlock_terminal();
    SetLastError(error);
    return result;
}


static BOOL console_input_w(HANDLE handle, INPUT_RECORD *records, DWORD length, DWORD *read, BOOL peek)
{
    if (!is_win9x()) {
        typedef BOOL (WINAPI *read_input_fn)(HANDLE, INPUT_RECORD *, DWORD, DWORD *);
        read_input_fn native = (read_input_fn)kernel_proc(peek ? "PeekConsoleInputW" : "ReadConsoleInputW");
        return native(handle, records, length, read);
    }

    BOOL result = peek ? PeekConsoleInputA(handle, records, length, read) :
        ReadConsoleInputA(handle, records, length, read);
    if (result) {
        UINT code_page = GetConsoleCP();
        for (DWORD i = 0; i < *read; ++i) {
            if (records[i].EventType != KEY_EVENT) {
                continue;
            }
            KEY_EVENT_RECORD *key = &records[i].Event.KeyEvent;
            CHAR encoded = key->uChar.AsciiChar;
            wchar_t decoded = 0;
            if (encoded != 0 && !MultiByteToWideChar(code_page, 0, &encoded, 1, &decoded, 1)) {
                decoded = 0xfffd;
            }
            key->uChar.UnicodeChar = decoded;
        }
    }
    return result;
}

THUNK(BOOL, ReadConsoleInputW, 16, (HANDLE handle, INPUT_RECORD *records, DWORD length, DWORD *read))
{
    return console_input_w(handle, records, length, read, FALSE);
}

THUNK(BOOL, PeekConsoleInputW, 16, (HANDLE handle, INPUT_RECORD *records, DWORD length, DWORD *read))
{
    return console_input_w(handle, records, length, read, TRUE);
}
