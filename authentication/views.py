from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth import login as auth_login, logout as auth_logout
from .forms import RegisterForm, LoginForm, NoteForm
from .models import User, Key, Note

def register(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            try:
                # Check if username already exists
                User.objects.get(username=User.encrypt_field(form.cleaned_data['username'], settings.MASTER_KEY)[0])
                form.add_error('username', 'Username already exists.')
                return render(request, 'authentication/register.html', {'form': form})
            except User.DoesNotExist:
                # Generate user-specific AES key
                aes_key = settings.MASTER_KEY  
                
                # Encrypt username and email
                username, iv_username = User.encrypt_field(form.cleaned_data['username'], aes_key)
                email, iv_email = User.encrypt_field(form.cleaned_data['email'], aes_key)
                
                # Hash password with salt
                password_hash, salt = User.hash_password(form.cleaned_data['password'])
                
                # Create user
                user = User(
                    username=username,
                    email=email,
                    password_hash=password_hash,
                    salt=salt,
                    iv_username=iv_username,
                    iv_email=iv_email
                )
                user.save()
                
                # Encrypt and store AES key
                encrypted_key, iv_key = Key.encrypt_key(aes_key, settings.MASTER_KEY)
                key = Key(user=user, encrypted_key=encrypted_key, iv=iv_key)
                key.save()
                
                # Log in the user after registration
                auth_login(request, user)
                return redirect('home')  # Redirect to home page
    else:
        form = RegisterForm()
    
    return render(request, 'authentication/register.html', {'form': form})

def login(request):
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            # Find user by encrypted username
            users = User.objects.all()
            user = None
            for u in users:
                try:
                    key = Key.objects.get(user=u)
                    aes_key = Key.decrypt_key(key.encrypted_key, key.iv, settings.MASTER_KEY)
                    decrypted_username = User.decrypt_field(u.username, u.iv_username, aes_key)
                    if decrypted_username == username:
                        user = u
                        break
                except (Key.DoesNotExist, ValueError):
                    continue
            
            if user and user.verify_password(password):
                auth_login(request, user)
                return redirect('home')  # Redirect to home page
            else:
                form.add_error(None, 'Invalid username or password.')
    else:
        form = LoginForm()
    
    return render(request, 'authentication/login.html', {'form': form})

def home(request):
    if not request.user.is_authenticated:
        return redirect('login')
    
    user = request.user
    key = Key.objects.get(user=user)
    aes_key = Key.decrypt_key(key.encrypted_key, key.iv, settings.MASTER_KEY)
    
    # Decrypt username
    try:
        decrypted_username = User.decrypt_field(user.username, user.iv_username, aes_key)
    except ValueError:
        decrypted_username = "User"  
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'delete_note':
            note_id = request.POST.get('note_id')
            try:
                note = Note.objects.get(id=note_id, user=user)
                note.delete()
                return redirect('home')
            except Note.DoesNotExist:
                pass  
        else:
            form = NoteForm(request.POST)
            if form.is_valid():
                content, iv_content = Note.encrypt_note(form.cleaned_data['content'], aes_key)
                note = Note(user=user, content=content, iv_content=iv_content)
                note.save()
                return redirect('home')
    else:
        form = NoteForm()
    
    # Decrypt and display user's notes
    notes = Note.objects.filter(user=user)
    decrypted_notes = []
    for note in notes:
        try:
            decrypted_content = Note.decrypt_note(note.content, note.iv_content, aes_key)
            decrypted_notes.append({
                'id': note.id,  
                'content': decrypted_content,
                'created_at': note.created_at
            })
        except ValueError:
            continue  
    
    return render(request, 'authentication/home.html', {
        'form': form,
        'notes': decrypted_notes,
        'decrypted_username': decrypted_username
    })

def logout(request):
    if request.method == 'POST':
        auth_logout(request)
        return redirect('login')
    return redirect('home')


