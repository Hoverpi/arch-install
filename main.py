import subprocess
import os
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.separator import Separator
import psutil
import re
import pexpect
import getpass
import sys

def run_command(cmd_list):
    try:
        print(f"Ejecutando: {' '.join(cmd_list)}")
        result = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            print(f"Error en comando: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(f"Error al ejecutar comando: {e}")
        return None


def check_existing_partitions(diskname):
    try:
        output = run_command(['lsblk', '-l', '-o', 'NAME', f'/dev/{diskname}'])
        if not output:
            return False
        partitions = [line for line in output.split('\n') if re.match(rf'{diskname}(p?\d+)', line)]
        return len(partitions) > 0
    except Exception as e:
        print(f"Error al verificar particiones: {e}")
        return False

def confirm_destructive_action(message):
    return inquirer.confirm(message=message, default=False).execute()


# Función para confirmar acciones destructivas
def confirm_action():
    return inquirer.confirm(
        message="¿Estás seguro de que deseas realizar cambios en el disco? Esto eliminará todos los datos existentes.",
        default=False
    ).execute()


def ask_diskname():
    return inquirer.select(
        message="¿Cuál es el nombre de tu disco principal para la instalación? (ej: sda, nvme0n1)",
        choices=['sda', 'nvme0n1'],
        default='nvme0n1'
    ).execute()

def ask_partition_creation():
    return inquirer.confirm(
        message="¿Deseas que el script cree las particiones automáticamente (EFI y LVM)?",
        default=True
    ).execute()

def ask_efi_partition_size():
    # Expresión regular para validar el formato del tamaño (número seguido de 'M' o 'G')
    size_pattern = re.compile(r'^\d+[MG]$', re.IGNORECASE)

    # Definir la pregunta a realizar al usuario
    size_input = inquirer.text(
        message="Ingresa el tamaño para la partición EFI (recomendado 500M o 1G). Formato: [número][M/G]",
        validate=lambda val: re.match(size_pattern, val) or 'Formato inválido. Usa números seguidos de "M" o "G".'
    ).execute()

    # Extraer el valor numérico y la unidad (M o G)
    size_value = int(size_input[:-1])
    size_unit = size_input[-1].upper()

    # Convertir el tamaño ingresado a megabytes para parted
    size_mb = size_value * 1024 if size_unit == 'G' else size_value

    return f"{size_mb}MiB" # Parted uses MiB

def ask_volumen_names():
    cryptname = inquirer.text(
        message="Nombre del volumen cifrado (ej: cryptlvm):",
        default="cryptlvm"
    ).execute()
    
    vgname = inquirer.text(
        message="Nombre del grupo LVM (ej: vg0):",
        default="vg0"
    ).execute()
    
    return cryptname, vgname

def create_partitions(diskname, efi_size):
    try:
        run_command(['parted', '-s', f'/dev/{diskname}', 'mklabel', 'gpt'])
        
        # Partición EFI
        run_command(['parted', '-s', f'/dev/{diskname}', 'mkpart', 'ESP', 'fat32', '1MiB', efi_size])
        run_command(['parted', '-s', f'/dev/{diskname}', 'set', '1', 'esp', 'on'])
        efi_part = f"{diskname}p1" if 'nvme' in diskname else f"{diskname}1"
        
        # Partición LVM
        run_command(['parted', '-s', f'/dev/{diskname}', 'mkpart', 'LVM', 'ext4', f'{efi_size}', '100%'])
        lvm_part = f"{diskname}p2" if 'nvme' in diskname else f"{diskname}2"
        
        return f"/dev/{efi_part}", f"/dev/{lvm_part}"
    except Exception as e:
        print(f"Error creando particiones: {e}")
        sys.exit(1)

def ask_sizepart(name):
    # Expresión regular para validar el formato del tamaño (número seguido de 'M' o 'G')
    size_pattern = re.compile(r'^\d+[MG]$', re.IGNORECASE)

    # Definir la pregunta a realizar al usuario
    size_input = inquirer.text(
        message=f"Ingresa el tamaño para {name}. Formato: [número][M/G]",
        validate=lambda val: re.match(size_pattern, val) or 'Formato inválido. Usa números seguidos de "M" o "G".'
    ).execute()

    # Extraer el valor numérico y la unidad (M o G)
    size_value = int(size_input[:-1])
    size_unit = size_input[-1].upper()

    return size_value, size_unit

# Función para preguntar al usuario sobre las opciones de cifrado
def ask_crypt_options(partname):
    cipher = inquirer.select(
        message="Selecciona el algoritmo de cifrado:",
        choices=['aes-xts-plain64', 'serpent-xts-plain64', 'twofish-xts-plain64'],
        default='aes-xts-plain64'
    ).execute()
    
    key_size = inquirer.select(
        message="Tamaño de la clave:",
        choices=[256, 512],
        default=256
    ).execute()
    
    hash_algo = inquirer.select(
        message="Algoritmo de hash:",
        choices=['sha256', 'sha512'],
        default='sha512'
    ).execute()
    
    pbkdf = inquirer.select(
        message="Algoritmo PBKDF:",
        choices=['argon2id', 'argon2i', 'pbkdf2'],
        default='argon2id'
    ).execute()
    
    label = inquirer.text(
        message="Etiqueta del volumen (opcional):",
        default=""
    ).execute()
    
    return {
        'cipher': cipher,
        'key_size': key_size,
        'hash': hash_algo,
        'pbkdf': pbkdf,
        'label': label
    }

# Función para crear un volumen cifrado LVM con opciones personalizadas
def set_cryptlvm(partition_path, cryptname):
    options = ask_crypt_options(partition_path)
    cmd = [
        'cryptsetup', 'luksFormat', partition_path,
        '--type', 'luks2',
        '--cipher', options['cipher'],
        '--key-size', str(options['key_size']),
        '--hash', options['hash'],
        '--pbkdf', options['pbkdf']
    ]
    if options['label']:
        cmd += ['--label', options['label']]
    
    password = getpass.getpass("Contraseña para cifrado: ")
    child = pexpect.spawn(' '.join(cmd))
    try:
        # 1. Esperar y confirmar sobrescritura
        child.expect(r'Are you sure\? \(Type \'yes\' in capital letters\):', timeout=30)
        child.sendline('YES')

        # 2. Ingresar contraseña
        child.expect('Enter passphrase for', timeout=10)
        child.sendline(password)

        # 3. Verificar contraseña
        child.expect('Verify passphrase:', timeout=10)
        child.sendline(password)
        
        # Esperar que termine
        child.expect(pexpect.EOF)
        
        print(f"Volumen cifrado configurado correctamente en {partition_path}.")
    except Exception as e:
        print(f"Error durante la configuración del cifrado: {e}")
        sys.exit(1)
    finally:
        child.close()

def create_lvm_structure(cryptname, vgname):
    try:
        run_command(['pvcreate', f'/dev/mapper/{cryptname}'])
        run_command(['vgcreate', vgname, f'/dev/mapper/{cryptname}'])
    except Exception as e:
        print(f"Error creando LVM: {e}")
        sys.exit(1)


def open_cryptlvm(partition_path, lvmname):
    print(f"Abriendo volumen cifrado en {partition_path} como {lvmname}...")
    
    # Solicitar contraseña
    password = getpass.getpass(prompt=f"Ingrese la contraseña para {partition_path}: ")
    
    # Utilizar pexpect para manejar la entrada de contraseña
    child = pexpect.spawn(f'cryptsetup open {partition_path} {lvmname}')
    
    try:
        child.expect('Enter passphrase for')
        child.sendline(password)
        child.expect(pexpect.EOF)
        print(f"Volumen cifrado abierto correctamente como /dev/mapper/{lvmname}.")
    except Exception as e:
        print(f"Error al abrir el volumen cifrado: {e}")
        sys.exit(1)
    finally:
        child.close()

# Función para crear un volumen físico (PV) y un grupo de volúmenes (VG)
def create_pv_vg(lvmname, vgname):
    part_path = f"/dev/mapper/{lvmname}"
    # Verificar si la partición existe
    if not os.path.exists(part_path):
        print(f"El dispositivo mapeado {part_path} no existe. Asegúrate de que el volumen cifrado esté abierto. Abortando.")
        sys.exit(1)

    # Crear el volumen físico (PV)
    print(f"Creando volumen físico en {part_path}...")
    run_command(['pvcreate', part_path])

    # Crear el grupo de volúmenes (VG)
    print(f"Creando grupo de volúmen {vgname}...")
    run_command(['vgcreate', vgname, part_path])

    print("Volumen físico y grupo creados exitosamente.")


# Función para crear los volúmenes LVM
def create_lvm_volumes(vgname, lvmname):
    print("Preguntando tamaños para volúmenes LVM (swap y root) dentro de /dev/mapper/{lvmname}")

    # Solicitar al usuario el tamaño para swap y root
    swap_size_value, swap_size_unit = ask_sizepart("volumen swap")

    # Crear el volumen de swap
    print(f"Creando volumen de swap de tamaño {swap_size_value}{swap_size_unit}")
    run_command(['lvcreate', '-L', f'{swap_size_value}{swap_size_unit}', vgname, '-n', 'swap'])

    # Crear volumen root con el espacio restante
    print("Creando volumen raíz con el espacio restante...")
    run_command(['lvcreate', '-l', '100%FREE', vgname, '-n', 'root'])
    print("Volúmenes lógicos LVM (swap y root) creados exitosamente.")


# Función para formatear las particiones
def format_partitions(efi_partition, vgname):
    lvm_root_path = f"/dev/{vgname}/root"
    lvm_swap_path = f"/dev/{vgname}/swap"
    
    # Formatear la partición EFI como FAT32
    if efi_partition:
        print(f"Formateando {efi_partition} como FAT32")
        run_command(['mkfs.fat', '-F32', '-n', 'EFI', efi_partition])
    else:
        print("No se proporcionó partición EFI, omitiendo formateo EFI.")

    # Formatear la partición raíz como EXT4
    print(f"Formateando {lvm_root_path} como EXT4")
    run_command(['mkfs.ext4', '-L', 'root', lvm_root_path])

    # Formatear la partición swap
    print(f"Formateando {lvm_swap_path} como swap")
    run_command(['mkswap', '-L', 'swap', lvm_swap_path])
    print("Particiones formateadas exitosamente.")

def is_mounted(mount_point):
    return os.path.ismount(mount_point)

# Función para montar particiones
def mount_partitions(efi_partition, vgname):
    lvm_root_path = f"/dev/{vgname}/root"
    lvm_swap_path = f"/dev/{vgname}/swap"

    # Verificar si las particiones existen
    partitions_to_check = []
    if efi_partition:
        partitions_to_check.append(efi_partition)
    partitions_to_check.append(lvm_root_path)
    partitions_to_check.append(lvm_swap_path)

    for partition in partitions_to_check:
        if not os.path.exists(partition):
            print(f"La partición {partition} no existe. Abortando.")
            sys.exit(1)

    # Montar la partición raíz LVM
    if not is_mounted('/mnt'):
        print("Montando la partición raíz LVM en /mnt...")
        run_command(['mount', lvm_root_path, '/mnt'])
    else:
        print("/mnt ya está montado, omitiendo montaje de raíz.")

    # Activar la partición de swap LVM
    print("Activando la partición swap LVM...")
    run_command(['swapon', lvm_swap_path])

    # Montar la partición EFI
    if efi_partition:
        efi_mount_point = '/mnt/efi'
        if not is_mounted(efi_mount_point):
            print(f"Montando la partición EFI {efi_partition} en {efi_mount_point}...")
            run_command(['mount', '--mkdir', '-o', 'uid=0,gid=0,fmask=0077,dmask=0077', efi_partition, efi_mount_point])
        else:
            print(f"{efi_mount_point} ya está montado, omitiendo montaje de EFI.")
    else:
        print("No se proporcionó partición EFI, omitiendo montaje de EFI.")

    print("Particiones montadas exitosamente.")


def ask_packages():
    # Definir categorías de paquetes
    base_packages = ['base', 'base-devel', 'linux-firmware', 'git']
    kernels = ['linux', 'linux-headers', 'linux-hardened', 'linux-hardened-headers', 'linux-zen', 'linux-zen-headers']
    network_packages = ['networkmanager', 'dnsmasq']
    bootloader_packages = ['grub']
    browser_packages = ['firefox']
    editor_packages = ['nano', 'vim']
    system_utilities = ['sudo', 'fastfetch']
    microcode_packages = ['intel-ucode', 'amd-ucode']
    bluetooth_packages = ['bluez', 'bluez-utils']
    audio_packages = ['pulseaudio', 'alsa-utils']
    security_packages = ['iptables', 'nftables', 'ufw', 'firewalld', 'fail2ban']
    additional_packages = ['openssl', 'ca-certificates', 'efibootmgr']

    # Crear opciones usando Choice
    choices = [
        Separator('= Paquetes Base =')
    ]
    
    # Paquetes base (siempre seleccionados)
    for pkg in base_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=True))
    
    # Kernels
    choices.append(Separator('= Kernels ='))
    for pkg in kernels:
        choices.append(Choice(
            name=pkg,
            value=pkg,
            enabled=(pkg in ['linux-hardened', 'linux-hardened-headers'])
        ))
    
    # Redes
    choices.append(Separator('= Paquetes de Red ='))
    for pkg in network_packages:
        choices.append(Choice(
            name=pkg,
            value=pkg,
            enabled=(pkg == 'networkmanager')
        ))
    
    # Bootloader
    choices.append(Separator('= Cargador de Arranque ='))
    for pkg in bootloader_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))

    # Browser
    choices.append(Separator('= Navegador ='))
    for pkg in browser_packages:
        choices.append(Choice(
            name=pkg,
            value=pkg,
            enabled=True  # Firefox habilitado por defecto
        ))
    
    # Editores
    choices.append(Separator('= Editores de Texto ='))
    for pkg in editor_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))
    
    # Utilidades
    choices.append(Separator('= Utilidades del Sistema ='))
    for pkg in system_utilities:
        choices.append(Choice(
            name=pkg,
            value=pkg,
            enabled=(pkg == 'sudo')
        ))
    
    # Microcódigo
    choices.append(Separator('= Microcódigo de CPU ='))
    for pkg in microcode_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))
    
    # Bluetooth
    choices.append(Separator('= Paquetes de Bluetooth ='))
    for pkg in bluetooth_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))
    
    # Audio
    choices.append(Separator('= Paquetes de Audio ='))
    for pkg in audio_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))
    
    # Seguridad
    choices.append(Separator('= Paquetes de Seguridad ='))
    for pkg in security_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))
    
    # Adicionales
    choices.append(Separator('= Paquetes Adicionales ='))
    for pkg in additional_packages:
        choices.append(Choice(name=pkg, value=pkg, enabled=False))

    # Preguntar al usuario con estilo personalizado
    selected = inquirer.checkbox(
        message="Selecciona los paquetes a instalar (SPACE para marcar):",
        choices=choices,
        validate=lambda result: len(result) > 0,
        instruction="(SPACE para seleccionar)"
    ).execute()
    
    return selected


def install_packages(selected_packages):
    # Crear una lista de paquetes seleccionados para pacstrap
    if not selected_packages:
        print("No se seleccionaron paquetes. Abortando la instalación de paquetes.")
        return

    # Preparar el comando pacstrap
    pacstrap_command = ['pacstrap', '-K', '/mnt'] + selected_packages

    # Ejecutar el comando pacstrap
    try:
        print("Instalando los paquetes seleccionados...")
        run_command(pacstrap_command)
        print("Paquetes instalados con éxito en /mnt.")
    except subprocess.CalledProcessError as e:
        print(f"Error al instalar los paquetes: {e}")
    except Exception as e:
        print(f"Ha ocurrido un error inesperado durante la instalación de paquetes: {e}")

def generate_fstab():
    print("Generando fstab...")
    run_command(['genfstab', '-pU', '/mnt', '>', '/mnt/etc/fstab'])
    print("fstab generado en /mnt/etc/fstab.")

def set_timezone():
    print("Configurando zona horaria...")
    run_command(['arch-chroot', '/mnt', 'ln', '-sf', '/usr/share/zoneinfo/America/Mexico_City', '/etc/localtime'])
    run_command(['arch-chroot', '/mnt', 'hwclock', '--systohc'])
    print("Zona horaria configurada.")

def configure_locale():
    print("Configurando idioma del sistema...")
    
    # Crear archivo locale.gen
    with open('/mnt/etc/locale.gen', 'w') as f:
        f.write("en_US.UTF-8 UTF-8\n")
    
    # Generar locales
    run_command(['arch-chroot', '/mnt', 'locale-gen'])
    
    # Crear archivo locale.conf
    with open('/mnt/etc/locale.conf', 'w') as f:
        f.write("LANG=en_US.UTF-8\n")
    
    # Configurar teclado
    with open('/mnt/etc/vconsole.conf', 'w') as f:
        f.write("KEYMAP=us\n")
    
    print("Idioma y teclado configurados.")

def set_hostname(hostname):
    print(f"Configurando hostname: {hostname}")
    
    # Crear archivo hostname
    with open('/mnt/etc/hostname', 'w') as f:
        f.write(f"{hostname}\n")
    
    # Configurar /etc/hosts
    hosts_content = f"""127.0.0.1\tlocalhost
::1\tlocalhost
127.0.1.1\t{hostname}.localdomain\t{hostname}
"""
    with open('/mnt/etc/hosts', 'w') as f:
        f.write(hosts_content)
    
    print("Hostname configurado.")

def create_user():
    """
    Gestiona la creación de usuarios y configuración de contraseñas en el sistema.
    """
    try:
        print("\n════════ Configuración de Usuarios ════════\n")
        
        user_type = inquirer.select(
            message="\nSelecciona el tipo de usuario a configurar:\n",
            choices=[
                Choice(
                    name="Configurar contraseña de root", 
                    value="root"
                ),
                Choice(
                    name="Crear nuevo usuario normal", 
                    value="new"
                )
            ],
            default="root"
        ).execute()

        if user_type == "root":
            if configure_root_user():
                return True
            return False
        else:
            if create_normal_user():
                return True
            return False

    except Exception as e:
        print(f"\nError crítico: {e}\n")
        return False

def configure_root_user():
    """Configura la contraseña del usuario root."""
    print("\nConfiguración de Root\n")
    
    try:
        password = get_validated_password(
            prompt="Ingresa la nueva contraseña para root:",
            min_length=1,
            require_confirmation=True,
            confirmation_prompt="Confirma la contraseña:"
        )
        
        print("\nEstableciendo contraseña...\n")
        if set_password("root", password):
            print("\n[Contraseña de root actualizada con éxito]\n")
            return True
        return False
    
    except Exception as e:
        print(f"\nError configurando root: {e}\n")
        return False


def create_normal_user():
    """Crea un usuario normal con validaciones básicas y opción para sudo."""
    print("\n\033[1;33mCreación de Nuevo Usuario\033[0m")
    
    username = inquirer.text(
        message="\033[1;37mNombre de usuario:\033[0m",
        validate=lambda val: (
            val != "root" and 
            len(val) >= 2 and
            re.match(r"^[a-z_][a-z0-9_-]*$", val)
        ) or "Nombre inválido (solo minúsculas, números y guiones, mínimo 2 caracteres)",
        transformer=lambda x: x.lower()
    ).execute()
    
    password = get_validated_password(
        prompt=f"Ingresa la contraseña para {username}:",
        min_length=0,
        require_confirmation=True,
        confirmation_prompt="Confirma la contraseña:"
    )
    
    sudo_access = inquirer.confirm(
        message=f"¿Otorgar permisos de administrador (sudo) a {username}?",
        default=False
    ).execute()

    if create_system_user(username, sudo_access) and set_password(username, password):
        configure_sudo(sudo_access)
        print(f"\n\033[1;32m✓ Usuario {username} creado exitosamente!\033[0m")
        return True
    return False


def get_validated_password(prompt, min_length=0, require_confirmation=True, confirmation_prompt=""):
    """Valida y confirma contraseñas de forma segura."""
    while True:
        password = inquirer.secret(
            message=prompt,
            validate=lambda val: len(val) >= min_length or f"Mínimo {min_length} caracteres" if min_length > 0 else True,
            transformer=lambda _: "\033[1;30m[contraseña oculta]\033[0m"
        ).execute()
        
        if not require_confirmation:
            return password
            
        confirmation = inquirer.secret(
            message=confirmation_prompt,
            validate=lambda val: val == password or "Las contraseñas no coinciden",
            transformer=lambda _: "\033[1;30m[contraseña oculta]\033[0m"
        ).execute()
        
        if password == confirmation:
            return password
        print("\033[1;31mLas contraseñas no coinciden, intenta nuevamente\033[0m")


def create_system_user(username, sudo_access):
    """Crea el usuario en el sistema con los grupos apropiados."""
    try:
        print(f"\nCreando usuario {username}...\n")
        cmd = ['arch-chroot', '/mnt', 'useradd', '-m', '-G', 'users']
        if sudo_access:
            cmd.extend(['-G', 'wheel'])
        cmd.append(username)
        
        result = run_command(cmd)
        if result is None or "error" in result.lower():
            raise Exception(f"Error al crear usuario: {result}")
        return True
        
    except Exception as e:
        print(f"\n{e}\n")
        return False


def set_password(username, password):
    """Establece la contraseña de forma segura usando chpasswd."""
    try:
        # Escapar caracteres especiales en la contraseña
        escaped_password = password.replace("'", r"'\''")
        cmd = f"echo '{username}:{escaped_password}' | chpasswd"
        
        result = run_command(['arch-chroot', '/mnt', 'bash', '-c', cmd])
        if result is not None and "error" in result.lower():
            raise Exception(f"Error al establecer contraseña: {result}")
        return True
        
    except Exception as e:
        print(f"\nError: {e}\n")
        if username != "root":
            run_command(['arch-chroot', '/mnt', 'userdel', '-r', username])
        return False


def configure_sudo(enabled):
    if not enabled:
        return
        
    print("\nConfigurando permisos sudo...\n")
    try:
        sudoers_file = '/mnt/etc/sudoers'
        with open(sudoers_file, 'r') as file:
            content = file.read()
        modified_content = re.sub(r'#\s*(wheel ALL=\(ALL:ALL\) ALL)', r'\1', content, flags=re.MULTILINE)
        with open(sudoers_file, 'w') as file:
            file.write(modified_content)
        
        # Usar run_command y acceder a returncode desde el objeto
        run_command(['arch-chroot', '/mnt', 'visudo', '-c'])
        
    except Exception as e:
        print(f"\n{e}\n")
        print("No se pudo configurar los permisos de sudo correctamente.")



def update_hooks_mkinitcpio_chroot():
    """
    Updates the HOOKS line in mkinitcpio.conf inside the chroot environment.
    Ensures proper hook order for LVM on LUKS setup.
    """
    file_path = "/etc/mkinitcpio.conf"
    # Updated hooks with systemd components for better LUKS+LVM support
    new_hooks = "HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt lvm2 filesystems fsck)"
    sed_command = f"sed -i 's/^HOOKS=.*/{new_hooks}/' {file_path}"

    print("Actualizando HOOKS en mkinitcpio.conf dentro del chroot...")
    try:
        run_command(['arch-chroot', '/mnt', 'sh', '-c', sed_command])
        print("El archivo mkinitcpio.conf ha sido actualizado dentro del chroot.")
    except Exception as e:
        print(f"Error al actualizar mkinitcpio.conf: {e}")
        sys.exit(1)

# set_bootentries_chroot
def set_kernelcommand_chroot(lvm_partition_path, lvmname, vgname):
    """
    Creates kernel command line parameters for boot with encrypted LVM.
    
    Args:
        lvm_partition_path: Path to the encrypted LUKS partition
        lvmname: Name of the LUKS mapper device
        vgname: Name of the LVM volume group
    """
    try:
        # Ensure directory exists
        run_command(['arch-chroot', '/mnt', 'mkdir', '-p', '/etc/cmdline.d'])
        file_path = "/etc/cmdline.d/root.conf"

        # Get UUID of the LUKS partition
        uuid = run_command(['blkid', lvm_partition_path, '-s', 'UUID', '-o', 'value']).strip()
        if not uuid:
                print(f"Error: No se pudo obtener UUID para {lvm_partition_path}")
                sys.exit(1)

        print('Configurando kernel command dentro del chroot')
        print(f'El uuid value es: {uuid} de la particion {lvm_partition_path}')

        kernel_command = f"rd.luks.name={uuid}={lvmname} root=/dev/{vgname}/root rw rootfstype=ext4 rd.shell=0 rd.emergency=reboot quiet"

        with open(f'/mnt/{file_path}', "w") as f:
            f.write(kernel_command)

        print("El archivo root.conf a sido creado y configurado dentro del chroot.")
    except Exception as e:
        print(f"Error al configurar kernel command: {e}")
        sys.exit(1)

def install_ukisign_dependences_chroot():
    """
    Install the required packages inside chroot:
    systemd-ukify, sbsigntools, efitools, and lvm2.
    """
    print("Instalando dependencias de UKI dentro del chroot...")
    try:
        # Update and install systemd-ukify, sbsigntools, efitools
        run_command(["arch-chroot", "/mnt", "pacman", "-Syu", "--noconfirm", "systemd-ukify", "sbsigntools", "efitools"])
        # Install lvm2 package
        run_command(["arch-chroot", '/mnt', "pacman", "-S", "--noconfirm", "lvm2"])
        print("Paquetes instalados dentro del chroot.")
    except Exception as e:
        print(f"Error al instalar dependencias UKI: {e}")
        print("Continuando con la instalación sin UKI...")


def create_uki_conf_chroot():
    """
    Creates /etc/kernel/uki.conf inside chroot with the required configuration.
    This file is used by systemd-ukify to create signed kernel images.
    """
    try:
        uki_conf_content = (
            "[UKI]\n"
            "OSRelease=@/etc/os-release\n"
            "PCRBanks=sha256\n\n"
            "[PCRSignature:initrd]\n"
            "Phases=enter-initrd\n"
            "PCRPrivateKey=/etc/kernel/pcr-initrd.key.pem\n"
            "PCRPublicKey=/etc/kernel/pcr-initrd.pub.pem\n"
        )
        with open("/mnt/etc/kernel/uki.conf", "w") as f:
            f.write(uki_conf_content)
        print("Created /etc/kernel/uki.conf dentro del chroot.")
    except Exception as e:
        print(f"Error al crear uki.conf: {e}")

def generate_pcr_key_chroot():
    """
    Generates the key for the PCR policy using systemd-ukify inside chroot.
    These keys are used for secure boot verification.
    """
    try:
        # Run the ukify genkey command with the configuration file inside chroot.
        print("Generando claves PCR policy dentro del chroot...")
        run_command(["arch-chroot", '/mnt', "ukify", "genkey", "--config=/etc/kernel/uki.conf"])
        print("PCR policy keys generated dentro del chroot.")
    except Exception as e:
        print(f"Error al generar claves PCR: {e}")
        print("Continuando sin generar claves PCR...")


def update_linux_preset_chroot(kernel="linux-hardened"):
    """
    Updates the kernel preset file to use UKI for boot.
    
    Args:
        kernel: Kernel name (default: "linux-hardened")
    """
    try:
        ensure_uki_directory_chroot()
        linux_preset_content = (
            "# mkinitcpio preset file for the 'linux' package\n\n"
            "#ALL_config=\"/etc/mkinitcpio.conf\"\n"
            f"ALL_kver=\"/boot/vmlinuz-{kernel}\"\n\n"
            "PRESETS=('default' 'fallback')\n\n"
            "#default_config=\"/etc/mkinitcpio.conf\"\n"
            f"default_image=\"/boot/initramfs-{kernel}.img\"\n"
            f"default_uki=\"/efi/EFI/Linux/arch-{kernel}.efi\"\n"
            "default_options=\"--splash /usr/share/systemd/bootctl/splash-arch.bmp\"\n\n"
            "#fallback_config=\"/etc/mkinitcpio.conf\"\n"
            f"fallback_image=\"/boot/initramfs-{kernel}-fallback.img\"\n"
            f"fallback_uki=\"/efi/EFI/Linux/arch-{kernel}-fallback.efi\"\n"
            "fallback_options=\"-S autodetect\"\n"
        )
        with open(f"/mnt/etc/mkinitcpio.d/{kernel}.preset", "w") as f:
            f.write(linux_preset_content)
        print(f"Updated /etc/mkinitcpio.d/{kernel}.preset dentro del chroot.")
        return True
    except Exception as e:
        print(f"Error al actualizar preset de {kernel}: {e}")
        return False


def ensure_uki_directory_chroot():
    """
    Ensure that the directory for UKI files exists inside chroot.
    """
    try:
        uki_dir = "/efi/EFI/Linux"
        run_command(['arch-chroot', '/mnt', 'mkdir', '-p', uki_dir])
        
        print(f"Directorio {uki_dir} creado correctamente dentro del chroot.")
        return True
    except Exception as e:
        print(f"Error al crear directorio UKI: {e}")
        return False


def regenerate_initramfs_chroot():
    """
    Regenerates the initramfs (UKI) for all presets inside chroot.
    This creates the unified kernel images used for boot.
    """
    try:
        print("Regenerando initramfs (UKI) dentro del chroot...")
        run_command(["arch-chroot", '/mnt', "mkinitcpio", "-P"])
        
        print("Initramfs regenerado correctamente dentro del chroot.")
        return True
    except Exception as e:
        print(f"Error al regenerar initramfs: {e}")
        sys.exit(1)
        return False



def is_uefi():
    """
    Verifies if the system is booting in UEFI or BIOS mode.
    
    Returns:
        bool: True if UEFI, False if BIOS
    """
    return os.path.exists("/sys/firmware/efi")

def install_bootloader_chroot(diskname, selected_packages):
    """
    Installs the appropriate bootloader based on the system type (UEFI or BIOS) inside chroot.
    """
    try:
        if 'grub' in selected_packages:
            # Instalar GRUB
            print("Instalando GRUB...")
            if is_uefi():
                run_command(["arch-chroot", '/mnt', "grub-install", "--target=x86_64-efi", 
                           f"--efi-directory=/efi", "--bootloader-id=grub", "--recheck"])
            else:
                run_command(["arch-chroot", '/mnt', "grub-install", "--target=i386-pc", 
                           f"/dev/{diskname}"])
            
            run_command(["arch-chroot", '/mnt', "grub-mkconfig", "-o", "/boot/grub/grub.cfg"])
            print("GRUB instalado correctamente.")
        
        else:
            # Usar systemd-boot solo en UEFI
            if not is_uefi():
                print("Error: systemd-boot requiere modo UEFI. Selecciona GRUB o usa BIOS.")
                sys.exit(1)
            
            print("Instalando systemd-boot...")
            run_command(["arch-chroot", '/mnt', "bootctl", "install"])
            
            print("systemd-boot instalado correctamente.")
        
        return True
    
    except Exception as e:
        print(f"Error al instalar el bootloader: {e}")
        return False

def enable_service_chroot(service):
    """
    Enables a systemd service inside chroot environment.
    Args:
        service: The name of the service to enable
    """
    try:
        print(f"Habilitando servicio {service} dentro del chroot...")
        result = run_command(["arch-chroot", '/mnt', "systemctl", "enable", service])
            
        print(f"Servicio {service} habilitado correctamente.")
        return True
    except Exception as e:
        print(f"Error al habilitar servicio {service}: {e}")
        return False

def install_NetworkManager_chroot():
    """
    Checks if the NetworkManager package is installed, installs it if not,
    and enables the service inside chroot.
    """
    try:
        print("Verificando si NetworkManager está instalado...")
        
        # Check if NetworkManager is installed using pacman inside chroot
        result = run_command(["arch-chroot", '/mnt', "pacman", "-Q", "networkmanager"])
        
        # Proper way to check if the package is installed
        if "networkmanager" in result.stdout.lower():
            print("NetworkManager ya está instalado dentro del chroot.")
        else:
            print("NetworkManager no está instalado dentro del chroot. Procediendo a instalar...")
            
            # Install NetworkManager with proper error checking
            run_command(["arch-chroot", '/mnt', "pacman", "-Syu", "--noconfirm", "networkmanager"])
                
            print("NetworkManager instalado correctamente.")
        
        # Enable the service
        if not enable_service_chroot("NetworkManager"):
            raise Exception("No se pudo habilitar el servicio NetworkManager")
            
        print("Configuración de NetworkManager completada correctamente.")
        return True
    except Exception as e:
        print(f"Error con NetworkManager: {e}")
        return False


def umount_all():
    """
    Unmounts all partitions mounted under /mnt.
    """
    try:
        print("Desmontando particiones de /mnt...")
        run_command(['umount', '-R', '/mnt'])
    except Exception as e:
        print(f"Error al desmontar: {e}")
        sys.exit(1)


def swapoff_all():
    """
    Deactivates all swap partitions.
    """
    try:
        print("Desactivando swap...")
        run_command(["swapoff", "-a"])
        return True
    except Exception as e:
        print(f"Error al desactivar swap: {e}")
        return False

def reboot_system():
    """
    Pregunta al usuario qué acción desea realizar: reiniciar, apagar o no hacer nada.
    """
    try:
        print("\n════════ Acciones del Sistema ════════")
        
        action = inquirer.select(
            message="¿Qué deseas hacer con el sistema?",
            choices=[
                Choice(  # Definir parámetros explícitamente
                    name="Reiniciar ahora",
                    value="reboot"
                ),
                Choice(
                    name="Apagar ahora",
                    value="shutdown"
                ),
                Choice(
                    name="Salir sin reiniciar/apagar",
                    value="exit"
                )
            ],
            instruction="(Para navegar, ENTER para seleccionar)"
        ).execute()

        if action == "reboot":
            print("\nReiniciando el sistema...")
            run_command(["reboot"])
        elif action == "shutdown":
            print("\nApagando el sistema...")
            run_command(["shutdown", "now"])
        else:
            print("\nSaliendo del script.")

    except Exception as e:
        print(f"\nError al ejecutar acción: {e}")

def exit_script():
    """
    Executes final actions before exiting.
    """
    print("Ejecutando operaciones finales antes de salir...")
    umount_all()  # Unmount all partitions
    swapoff_all()  # Deactivate swap
    reboot_system()  # Ask what to do with the system
    print("Operaciones completadas. Saliendo del script.")


# ------------Main---------------

def main():
    print("=== Script de Instalación de Arch Linux con LVM sobre LUKS ===")
    
    # 1. Selección de disco
    diskname = ask_diskname()
    
    # Verificar particiones existentes
    if check_existing_partitions(diskname):
        print(f"¡Advertencia! El disco /dev/{diskname} contiene particiones existentes.")
        if not confirm_destructive_action("¿Deseas eliminar todas las particiones y continuar? (Se perderán todos los datos)"):
            print("Operación cancelada por el usuario.")
            sys.exit(0)

    # 2. Configuración de particiones
    if ask_partition_creation():
        efi_size = ask_efi_partition_size()
        if confirm_destructive_action("¿Confirmas la creación de nuevas particiones? (Se borrarán los datos existentes)"):
            efi_partition, lvm_partition = create_partitions(diskname, efi_size)
        else:
            sys.exit(0)
    else:
        # Usar particiones existentes
        efi_partition = f"/dev/{diskname}1" if 'nvme' not in diskname else f"/dev/{diskname}p1"
        lvm_partition = f"/dev/{diskname}2" if 'nvme' not in diskname else f"/dev/{diskname}p2"
        if not all(os.path.exists(p) for p in [efi_partition, lvm_partition]):
            print("¡Error! Particiones requeridas no existen")
            sys.exit(1)

    # 3. Configuración LUKS
    cryptname, vgname = ask_volumen_names()
    set_cryptlvm(lvm_partition, cryptname)
    open_cryptlvm(lvm_partition, cryptname)
    
    # 4. Configuración LVM
    create_pv_vg(cryptname, vgname)
    
    # 5. Crear volúmenes lógicos
    swap_size, _ = ask_sizepart("swap")
    run_command(['lvcreate', '-L', f'{swap_size}G', vgname, '-n', 'swap'])
    run_command(['lvcreate', '-l', '100%FREE', vgname, '-n', 'root'])
    
    # 6. Formatear particiones
    format_partitions(efi_partition, vgname)
    
    # 7. Montar particiones
    mount_partitions(efi_partition, vgname)
    
    # 8. Instalar paquetes base
    selected_packages = ask_packages()
    install_packages(selected_packages)
    
    # 9. Configuración básica del sistema
    generate_fstab()
    set_timezone()
    configure_locale()
    
    # 10. Configurar hostname
    hostname = inquirer.text(message="Ingresa el hostname:").execute()
    set_hostname(hostname)
    
    # 11. Configurar usuarios
    create_user()
    create_user()

    # 12. Configurar arranque
    update_hooks_mkinitcpio_chroot()
    set_kernelcommand_chroot(lvm_partition, cryptname, vgname)
    
    # 13. Configurar UKI (solo UEFI)
    if is_uefi():
        install_ukisign_dependences_chroot()
        create_uki_conf_chroot()
        generate_pcr_key_chroot()
        kernel = "linux"
        if "linux-zen" in selected_packages: kernel = "linux-zen"
        elif "linux-hardened" in selected_packages: kernel = "linux-hardened"
        update_linux_preset_chroot(kernel)
        regenerate_initramfs_chroot()
    
    # 14. Instalar bootloader
    install_bootloader_chroot(diskname, selected_packages)
    
    # 15. Habilitar servicios esenciales
    install_NetworkManager_chroot()
    
    # 16. Finalizar
    print("\n=== Instalación completada ===")
    exit_script()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInstalación cancelada")
        exit_script()
    except Exception as e:
        print(f"Error crítico: {e}")
        sys.exit(1)