PAGE_HEADER_1 = "C6.2 Alphabetical list of A64 base instructions"
SECTION_TITLE_1 = "C6.2.%d"   # instr number from 1 to 348 inclusive

PAGE_HEADER_2 = "C7.2 Alphabetical list of A64 Advanced SIMD and floating-point instructions"
SECTION_TITLE_2 = "C7.2.%d"   # instr number from 1 to 404 inclusive

DIRTY_BEGINS = "31"

SYNTAX = "%s"    # instr name

def search_page_header(f, page_header):
    for line in f:
        if line.strip() == page_header:
            return line

    raise StopIteration()

def search_section_title(f, title):
    for line in f:
        line = line.strip()
        if not line:
            continue

        if line == title:
            return line
        else:
            return False

    raise StopIteration()

def search_instr_title(f):
    for line in f:
        line = line.strip()
        if not line:
            continue

        return line
    raise StopIteration()


def search_instr_description(f):
    descr = []
    for line in f:
        line = line.strip()
        if line.startswith(DIRTY_BEGINS):
            return ' '.join(descr)

        descr.append(line)
    return ' '.join(descr)

def process_description(descr):
    descr = descr.replace('\u2022', '\n  -')
    return descr

def search_syntaxes(f, instr_name):
    token = SYNTAX % instr_name
    syntaxes = []
    cnt = 30
    found = False
    for line in f:
        line = line.strip()
        if line.startswith(token):
            found = True
            cnt = 10
            syntaxes.append(line)
        elif line == "Assembler symbols":
            return '\n'.join(syntaxes)

        cnt -= 1

        if cnt < 0:
            return '\n'.join(syntaxes)

    return '\n'.join(syntaxes)


def parse(f, page_header, section_tmpl):
    ret = []
    num = 1
    first_section = None
    last_section = None
    try:
        while True:
            on_section = False
            section_title = section_tmpl % num
            while not on_section:
                search_page_header(f, page_header)
                on_section = search_section_title(f, section_title) != False

            if first_section is None:
                first_section = section_title

            title = search_instr_title(f)
            name = title.split()[0]
            descr = search_instr_description(f)
            syntaxes = search_syntaxes(f, name)

            descr = process_description(descr)

            last_section = section_title
            ret.append((section_title, title, name.lower(), descr, syntaxes))
            num += 1
    except StopIteration:
        print("Sections %s to %s (inclusive) were found." % (first_section, last_section))
        return ret

if __name__ == '__main__':
    import sys, json
    src1, src2, dst = sys.argv[1:]      # C6.2.txt  C7.2.txt
    ret = []
    with open(src1, 'rt') as f:
        ret.extend(parse(f, PAGE_HEADER_1, SECTION_TITLE_1))
    with open(src2, 'rt') as f:
        ret.extend(parse(f, PAGE_HEADER_2, SECTION_TITLE_2))

    ret.append(
            ("", "Reference", "reference", "Arm Architecture Reference Manual Armv8, for Armv8-A architecture profile\nhttps://developer.arm.com/documentation/ddi0487/latest/\n2021-01-01", "")
            )
    with open(dst, 'wt') as f:
        json.dump(ret, f, indent=2)

