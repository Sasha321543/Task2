import pefile
def analyze_pe(file_path):
    pe = pefile.PE(file_path)
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print(f"Імпортовані бібліотеки та функції з файлу {file_path}:\n")
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"\nБiблiотека: {entry.dll.decode('utf-8')}")
            for imp in entry.imports:
                function_name = imp.name.decode('utf-8') if imp.name else None
                if function_name:
                    print(f"  - {function_name}")
                else:
                    print(f"  - (Без імені функції)")
    else:
        print("Імпортовані бібліотеки не знайдено в цьому файлі.")

if __name__ == "__main__":
    file_path = input("Введіть шлях до PE-файлу: ")
    
    analyze_pe(file_path)