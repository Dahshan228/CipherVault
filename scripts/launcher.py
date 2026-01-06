REQUIRED_PACKAGES = {
    "cryptography": "cryptography",
    "typer": "typer",
    "rich": "rich",
    "customtkinter": "customtkinter",
    "pillow": "PIL",  # Package is Pillow, but import is PIL
    "packaging": "packaging"
}

def check_dependencies():
    """
    Checks if required packages are installed.
    Returns a list of missing packages (pypi names).
    """
    # If running as a PyInstaller executable, dependencies are bundled.
    if getattr(sys, 'frozen', False):
        return []

    missing = []
    for package_name, import_name in REQUIRED_PACKAGES.items():
        if importlib.util.find_spec(import_name) is None:
            missing.append(package_name)
    return missing

def install_packages(packages):
    """
    Installs missing packages using pip.
    """
    print(f"Installing missing packages: {', '.join(packages)}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *packages])
        print("Installation successful!")
        return True
    except subprocess.CalledProcessError:
        print("Failed to install packages.")
        return False

def main():
    print("Checking dependencies...")
    missing = check_dependencies()

    if missing:
        print("The following dependencies are missing:")
        for p in missing:
            print(f" - {p}")
        
        while True:
            choice = input("\nDo you want to install them now? (y/n): ").strip().lower()
            if choice == 'y':
                if install_packages(missing):
                    break
                else:
                    input("Press Enter to exit...")
                    sys.exit(1)
            elif choice == 'n':
                print("Cannot run without dependencies.")
                input("Press Enter to exit...")
                sys.exit(1)
            else:
                print("Invalid choice.")

    # dependencies are present, launch the app
    try:
        # We import here to avoid ImportErrors at the top level
        from cipher_vault.gui import main as gui_main
        print("Starting CipherVault...")
        gui_main()
    except Exception as e:
        print(f"Error launching application: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
