import os
import re
import sys
import textwrap

# ==========================================
# ⚙️ CONFIGURATION: pass a path on the CLI instead:
#     python piyoxml.py path/to/Contract.sol
# ==========================================


def cdata(text: str) -> str:
    """Wrap text in a CDATA section safely: a literal ']]>' inside the content
    is escaped using the standard split technique so real XML parsers never
    choke (audit fix: expressions like a[b[c]]>=x used to break CDATA)."""
    safe = text.replace("]]>", "]]]]><![CDATA[>")
    return f"<![CDATA[{safe}]]>"

def create_index_mask(text):
    """
    Creates a 'ghost copy' of the file where comments and strings are replaced 
    by blank spaces. This unified regex processes left-to-right, ensuring that 
    quotes inside comments or slashes inside strings do not corrupt the parser.
    """
    # Matches strings OR block comments OR line comments in one pass
    pattern = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(/\*[\s\S]*?\*/)|(//.*)'
    
    def replacer(match):
        return ' ' * len(match.group(0))
    
    return re.sub(pattern, replacer, text)

def parse_solidity_to_xml(file_path) -> str:
    if not os.path.exists(file_path):
        print(f" Error: File '{file_path}' not found.")
        return None

    file_name = os.path.basename(file_path)
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        full_text = f.read()

    # Generate the ghost mask
    masked_text = create_index_mask(full_text)

    xml_output = [f'<source_file name="{file_name}" language="solidity">']
    
    # Extract Environment Setup (Pragmas, Imports) using the mask to find coordinates
    env_matches = list(re.finditer(r'\b(pragma|import)\b[^;]+;', masked_text))
    if env_matches:
        xml_output.append("    <environment_setup>")
        for m in env_matches:
            # Extract the raw statement using coordinates found in the mask
            raw_statement = full_text[m.start():m.end()].strip()
            xml_output.append(f"        {cdata(raw_statement)}")
        xml_output.append("    </environment_setup>\n")

    # Extract Top-Level Containers (contract, interface, library)
    block_pattern = r'\b(contract|interface|library)\s+([a-zA-Z0-9_]+)'
    
    search_idx = 0
    while True:
        match = re.search(block_pattern, masked_text[search_idx:])
        if not match: 
            break
            
        b_type = match.group(1)
        b_name = match.group(2)
        start_idx = search_idx + match.end()
        
        # Find the opening brace
        open_brace_idx = masked_text.find('{', start_idx)
        if open_brace_idx == -1: 
            break
            
        # Safely count braces to find the exact end of this specific contract/interface
        brace_count = 1
        close_brace_idx = -1
        for i in range(open_brace_idx + 1, len(masked_text)):
            if masked_text[i] == '{': brace_count += 1
            elif masked_text[i] == '}': 
                brace_count -= 1
                if brace_count == 0:
                    close_brace_idx = i
                    break
                    
        if close_brace_idx != -1:
            inner_start = open_brace_idx + 1
            inner_end = close_brace_idx
            
            # Process the inside of the block
            processed_block = process_inner_block(b_type, b_name, inner_start, inner_end, full_text, masked_text)
            xml_output.append(processed_block)
            
            # Move the search index past this entire contract to find the next one
            search_idx = close_brace_idx + 1
        else:
            break

    xml_output.append('</source_file>')
    final_xml = "\n".join(xml_output)

    return final_xml

def process_inner_block(b_type, b_name, inner_start, inner_end, original, masked, indent="    "):
    """Separates state elements from execution logic reliably using coordinate mapping."""
    inner_xml = [f'{indent}<{b_type} name="{b_name}">']
    
    # Find execution logic boundaries using only the mask
    func_pattern = r'\b(function|constructor|modifier|fallback|receive)\b'
    func_matches = list(re.finditer(func_pattern, masked[inner_start:inner_end]))
    
    functions_data = []
    is_func_char = [False] * (inner_end - inner_start)
    
    for fm in func_matches:
        f_start = fm.start() + inner_start
        f_keyword = fm.group(1)

        # Extract precise name anchored to the keyword.
        # A 'function' keyword followed directly by '(' is a FUNCTION-TYPE
        # STATE VARIABLE (e.g. `function(uint) external callback;`) — it must
        # stay in <state_variables>, not be carved out as a function.
        if f_keyword == 'function':
            if not re.match(r'\bfunction\s+[A-Za-z_$][\w$]*\s*\(', masked[f_start:inner_end]):
                continue
        name = f_keyword
        if f_keyword in ['function', 'modifier']:
            name_match = re.match(r'\b(?:function|modifier)\s+([a-zA-Z0-9_]+)', masked[f_start:inner_end])
            if name_match:
                name = name_match.group(1)
                
        # Find the end of this function/modifier definition
        f_end = -1
        brace_count = 0
        has_opened = False
        
        for i in range(f_start, inner_end):
            if masked[i] == ';':
                if not has_opened:
                    f_end = i + 1
                    break
            elif masked[i] == '{':
                has_opened = True
                brace_count += 1
            elif masked[i] == '}':
                brace_count -= 1
                if has_opened and brace_count == 0:
                    f_end = i + 1
                    break
                    
        if f_end == -1: f_end = inner_end
            
        # Walk BACKWARDS through blank spaces in the mask to capture NatSpec comments.
        real_start = f_start
        for i in range(f_start - 1, inner_start - 1, -1):
            if masked[i].strip() == '':
                real_start = i
            else:
                break
        
        # Determine the structural type and standardize unnamed special functions for AI routing
        if not has_opened:
            f_type = 'interface_declaration'
        elif f_keyword in ['fallback', 'receive']:
            f_type = 'fallback_receive'
            name = f"special_{f_keyword}"
        else:
            f_type = 'constructor' if f_keyword == 'constructor' else f_keyword
        
        functions_data.append({
            'name': name,
            'type': f_type,
            'code': original[real_start:f_end]
        })
        
        # Log these coordinates so we can subtract them from the state variables
        for i in range(real_start - inner_start, f_end - inner_start):
            is_func_char[i] = True

    # Build the State Variables map by gathering whatever characters do NOT belong to a function
    state_chars = []
    for i in range(inner_end - inner_start):
        if not is_func_char[i]:
            state_chars.append(original[inner_start + i])
        else:
            # Preserve line breaks for formatting, but blank out the function code
            if original[inner_start + i] == '\n':
                state_chars.append('\n')
            else:
                state_chars.append(' ')
                
    state_text = "".join(state_chars)
    
    # Format State Variables cleanly
    state_lines_unfiltered = [line for line in state_text.splitlines() if line.strip()]
    if state_lines_unfiltered:
        state_text_clean = "\n".join(state_lines_unfiltered)
        state_dedented = textwrap.dedent(state_text_clean).strip()
        clean_state = "\n".join([f"{indent}        {line}" for line in state_dedented.splitlines()])

        inner_xml.append(f'{indent}    <state_variables>')
        inner_xml.append(f'{indent}        {cdata(chr(10) + clean_state + chr(10) + indent + "        ")}')
        inner_xml.append(f'{indent}    </state_variables>')

    # Format Functions cleanly
    for fd in functions_data:
        inner_xml.append(f'{indent}    <function name="{fd["name"]}" type="{fd["type"]}">')
        func_code_dedented = textwrap.dedent(fd["code"]).strip()
        func_code_formatted = "\n".join([f"{indent}        {line}" for line in func_code_dedented.splitlines()])

        inner_xml.append(f'{indent}        {cdata(chr(10) + func_code_formatted + chr(10) + indent + "        ")}')
        inner_xml.append(f'{indent}    </function>')
        
    inner_xml.append(f'{indent}</{b_type}>')
    return "\n".join(inner_xml)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python piyoxml.py <path/to/Contract.sol>")
        sys.exit(1)
    result = parse_solidity_to_xml(sys.argv[1])
    if result:
        print(result)