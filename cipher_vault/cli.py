import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from pathlib import Path
from .core import CipherVaultCore
import os

app = typer.Typer(
    name="CipherVault",
    help="Professional File Encryption Tool",
    add_completion=False,
    no_args_is_help=True
)
console = Console()
core = CipherVaultCore()

@app.command()
def generate_key(
    output_path: Path = typer.Option("secret.key", "--output", "-o", help="Path to save the generated key"),
    show: bool = typer.Option(False, "--show", "-s", help="Display the key in the terminal")
):
    """
    Generate a new secure encryption key.
    """
    key = core.generate_key()
    
    try:
        with open(output_path, "wb") as f:
            f.write(key)
        
        rprint(Panel(f"[green]Key generated successfully![/green]\nSaved to: [bold]{output_path}[/bold]", title="Success"))
        
        if show:
            rprint(f"Key: [yellow]{key.decode()}[/yellow]")
            rprint("[red]WARNING: Keep this key secret![/red]")
            
    except Exception as e:
        console.print(f"[red]Error saving key: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
def encrypt(
    input_file: Path = typer.Argument(..., help="File to encrypt", exists=True),
    output_file: Path = typer.Option(None, "--output", "-o", help="Output file path (default: input_file.enc)"),
    key_file: Path = typer.Option(None, "--key-file", "-k", help="Path to the key file"),
    password: str = typer.Option(None, "--password", "-p", help="Password to derive key from"),
    key: str = typer.Option(None, "--key", help="Raw key string")
):
    """
    Encrypt a file using a key or password.
    """
    if not output_file:
        output_file = Path(f"{input_file}.enc")

    # Determine key source
    final_key = None
    salt = None
    
    if key:
        final_key = key.encode()
    elif key_file:
        if not key_file.exists():
            console.print(f"[red]Key file not found: {key_file}[/red]")
            raise typer.Exit(code=1)
        with open(key_file, "rb") as f:
            final_key = f.read().strip()
    elif password:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Deriving key from password...", total=None)
            final_key, salt = core.derive_key_from_password(password)
            # We need to save the salt for decryption if using password
            # For simplicity in this CLI version, we'll prepend salt to output or assume user manages it.
            # BUT, to make it professional, we should probably prepend the salt to the file if password is used.
            # Let's stick to simple key management for now or warn user about salt.
            # Actually, standard practice: prepend salt (16 bytes) to the encrypted file.
    else:
        console.print("[red]Error: You must provide a key (--key), a key file (--key-file), or a password (--password).[/red]")
        raise typer.Exit(code=1)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description=f"Encrypting {input_file.name}...", total=None)
            
            with open(input_file, 'rb') as f:
                data = f.read()
            
            encrypted_data = core.encrypt_data(data, final_key)
            
            with open(output_file, 'wb') as f:
                if salt:
                    f.write(salt) # Prepend salt if password derived
                f.write(encrypted_data)

        rprint(Panel(f"[green]File encrypted successfully![/green]\nOutput: [bold]{output_file}[/bold]", title="Success"))
        if salt:
             rprint("[blue]Note: Salt has been prepended to the file for password derivation.[/blue]")

    except Exception as e:
        console.print(f"[red]Encryption failed: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
def decrypt(
    input_file: Path = typer.Argument(..., help="File to decrypt", exists=True),
    output_file: Path = typer.Option(None, "--output", "-o", help="Output file path (default: remove .enc extension)"),
    key_file: Path = typer.Option(None, "--key-file", "-k", help="Path to the key file"),
    password: str = typer.Option(None, "--password", "-p", help="Password to derive key from"),
    key: str = typer.Option(None, "--key", help="Raw key string")
):
    """
    Decrypt a file using a key or password.
    """
    if not output_file:
        # Try to remove .enc extension, otherwise append .dec
        if input_file.suffix == ".enc":
            output_file = input_file.with_suffix("")
        else:
            output_file = input_file.with_suffix(".dec")

    try:
        final_key = None
        start_offset = 0 # To skip salt if present
        
        if key:
            final_key = key.encode()
        elif key_file:
             if not key_file.exists():
                console.print(f"[red]Key file not found: {key_file}[/red]")
                raise typer.Exit(code=1)
             with open(key_file, "rb") as f:
                final_key = f.read().strip()
        elif password:
            # If password is used, read first 16 bytes as salt
            with open(input_file, 'rb') as f:
                salt = f.read(16)
            start_offset = 16
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            ) as progress:
                progress.add_task(description="Deriving key from password...", total=None)
                final_key, _ = core.derive_key_from_password(password, salt)
        else:
            console.print("[red]Error: You must provide a key, key file, or password.[/red]")
            raise typer.Exit(code=1)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description=f"Decrypting {input_file.name}...", total=None)
            
            with open(input_file, 'rb') as f:
                f.seek(start_offset)
                encrypted_data = f.read()
            
            try:
                decrypted_data = core.decrypt_data(encrypted_data, final_key)
            except Exception:
                console.print("[red]Decryption failed: Invalid key or corrupted data.[/red]")
                raise typer.Exit(code=1)

            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

        rprint(Panel(f"[green]File decrypted successfully![/green]\nOutput: [bold]{output_file}[/bold]", title="Success"))

    except Exception as e:
        console.print(f"[red]Decryption process failed: {e}[/red]")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
