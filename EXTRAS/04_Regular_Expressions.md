## Regular Expressions (Regex) — Fundamentals

### What is Regex?
Patterns of text defined to search documents and match exactly what you're looking for.
More powerful than simple string search — matches patterns, not just exact strings.

```bash
# Simple string search
grep 'string' file.txt

# Regex pattern search
grep '[pattern]' file.txt
```

---

### Character Sets (Charsets)

Defined with `[ ]` square brackets — matches any one character inside.

```
[abc]        matches: a, b, or c (any single occurrence)
[abc]zz      matches: azz, bzz, czz
```

---

### Ranges with `-`

```
[a-c]zz      matches: azz, bzz, czz
[a-cx-z]zz   matches: azz, bzz, czz, xzz, yzz, zzz
[a-zA-Z]     matches: any single letter (upper or lowercase)
[0-9]        matches: any single digit
file[1-3]    matches: file1, file2, file3
```

---

### Exclusion with `^`

Inside `[ ]`, `^` means "NOT these characters":

```
[^k]ing      matches: ring, sing, $ing  (NOT king)
[^a-c]at     matches: fat, hat          (NOT bat, cat)
```

---

### Examples from Image

| Goal | Regex |
|------|-------|
| Match c, o, g | `[cog]` |
| Match cat, fat, hat | `[cfh]at` |
| Match Cat, cat, Hat, hat | `[CcHh]at` |
| Match File1–File9, file1–file9 | `[Ff]ile[1-9]` |
| Match above EXCEPT File7 | `[Ff]ile[^7]` |

---

### Important Notes

**Charset ≠ String:**
```
[abc] matches: a, b, c individually — not the string "abc" in order
              it matches any occurrence of those characters
```

**Be specific but not too specific:**
```
Match a,b,c → use [a-c]  not [a-z]    ← too broad
Match a,c,f,r,s,z → use [a-z]         ← range is cleaner than listing all
```

**Write characters in the order they appear in questions** to match expected answers.

---

### Regex Efficiency Rule
```
Too specific:  [abc]  when [a-c] works  → unnecessarily verbose
Too broad:     [a-z]  when [a-c] needed → matches too much
Just right:    Match the minimum range that satisfies the requirement
```

---

## Regex — Wildcards & Optional Characters

### The `.` Dot — Wildcard
Matches **any single character** except line break.

```
a.c    matches: aac, abc, a0c, a!c, a.c, a@c ...
.at    matches: Cat, fat, hat, rat, @at, 1at ...
```

---

### The `?` Question Mark — Optional Character
Makes the **preceding character optional** (0 or 1 occurrence).

```
abc?   matches: ab, abc        (c is optional)
[Cc]ats?  matches: Cat, Cats, cat, cats
```

---

### Escaping with `\` — Literal Characters
Use `\` to match special characters literally.

```
a.c    matches: abc, a0c, a@c, a.c  (dot = any char)
a\.c   matches: a.c ONLY            (dot = literal dot)

cat\.xyz  matches: cat.xyz ONLY
```

---

### Examples from Image

| Goal | Regex | Explanation |
|------|-------|-------------|
| Match Cat, fat, hat, rat | `.at` | `.` = any char before `at` |
| Match Cat, cats | `[Cc]ats?` | `[Cc]` = C or c, `s?` = s optional |
| Match cat.xyz | `cat\.xyz` | `\.` = literal dot |
| Match cat.xyz, cats.xyz, hats.xyz | `[ch]ats?\.xyz` | charset + optional s + literal dot |
| Match 4-letter string not ending n-z | `...[^n-z]` | 3 wildcards + excluded range |
| Match bat, bats, hat, hats (not rat/rats) | `[^r]ats?` | exclude r + optional s |

---

## Regex — Metacharacters & Repetitions

### Metacharacters (Shorthand Charsets)

| Metachar | Matches | Example |
|----------|---------|---------|
| `\d` | Any digit (0-9) | `\d` → 9, 0, 3 |
| `\D` | Any non-digit | `\D` → A, @, ! |
| `\w` | Any alphanumeric + underscore | `\w` → a, 3, _ |
| `\W` | Any non-alphanumeric (no underscore) | `\W` → !, #, @ |
| `\s` | Whitespace (space, tab, line break) | `\s` → " " |
| `\S` | Non-whitespace (alphanumeric + symbols) | `\S` → a, 1, ! |

> **Note:** `\w` includes underscores `_` — so `test_file` is fully matched by `\w+`

---

### Repetition Quantifiers

| Quantifier | Matches | Example |
|-----------|---------|---------|
| `{12}` | Exactly 12 times | `z{12}` → zzzzzzzzzzzz |
| `{1,5}` | 1 to 5 times | `a{1,5}` → a, aa, aaa, aaaa, aaaaa |
| `{2,}` | 2 or more times | `a{2,}` → aa, aaa, aaaa... |
| `*` | 0 or more times | `cats*` → cat, cats, catss, catsss |
| `+` | 1 or more times | `br+` → br, brr, brrr... |
| `?` | 0 or 1 time (optional) | `cats?` → cat, cats |

---

### Examples from Images

| Goal | Regex | Explanation |
|------|-------|-------------|
| Match catssss | `cats{4}` | s exactly 4 times |
| Match Cat, cats, catsss | `[Cc]ats*` | s zero or more times |
| Match regex go br, regex go brrrrrr | `regex go br+` | r one or more times |
| Match ab0001, bb0000, abc1000, etc. | `[abc]{1,3}[01]{4}` | 1-3 letters + 4 digits (0 or 1) |
| Match File01, File2, file12, File99 | `[Ff]ile\d{1,2}` | 1-2 digits at end |
| Match kali tools, kali   tools | `kali\s+tools` | one or more spaces |
| Match notes~, stuff@, gtfob#, lmaoo! | `\w{5}\W` | 5 word chars + 1 non-word |
| Match "2f0h@f0j0%! a)K!F49h!FFOK" | `\S*\s*\S*` | non-space, optional space, non-space |
| Match 9-char string not ending in ! | `\S{8}[^!]` | 8 any + 1 not ! |
| Match .bash_rc, .unnecessarily_long_filename, note1 | `\.?\w+` | optional dot + word chars |

---

### Quick Combination Examples

```regex
\d{4}           → exactly 4 digits (e.g. 2024)
[A-Z]\w+        → capital letter followed by 1+ word chars
\s+             → one or more whitespace chars
\S{8}[^!]       → 8 non-whitespace chars + 1 char that isn't !
\w{5}\W         → 5 alphanumeric/underscore + 1 symbol
[Ff]ile\d{1,2}  → File or file + 1-2 digit number
\.?\w+          → optional dot + one or more word characters
```
