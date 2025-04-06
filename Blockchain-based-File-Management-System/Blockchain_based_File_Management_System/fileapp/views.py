import os
import json
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect, get_object_or_404
from django.http import FileResponse, Http404, HttpResponse, HttpResponseForbidden
from django.core.files.storage import FileSystemStorage, default_storage
from django.db.models import Q
import hashlib
import mimetypes
from .models import FileUpload, Block, FilePart, KeyStorage
from .models import FileUploadManager

# Modified upload_file view to handle file splitting
@login_required
def upload_file(request):
    if request.method == "POST":
        uploaded_file = request.FILES.get("file")

        if uploaded_file:
            try:
                # Split and encrypt the file
                file_hash, part_info = FileUploadManager.split_and_encrypt_file(
                    uploaded_file, request.user, num_parts=5
                )
                print(f"File hash: {file_hash}")
                print(f"Part info: {part_info}")  # Debug: Print part info

                # Save the file metadata in the database
                file_instance = FileUpload.objects.create(
                    file=uploaded_file,
                    file_hash=file_hash,
                    user=request.user
                )

                # Save each file part and encryption key
                for part in part_info:
                    # Save encryption key
                    key_storage = KeyStorage.objects.create(
                        user=request.user,
                        key_id=part['key_id'],
                        encrypted_key=part['encrypted_key']
                    )

                    # Save file part
                    FilePart.objects.create(
                        file_upload=file_instance,
                        part_number=part['part_number'],
                        part_hash=part['part_hash'],
                        encrypted_part=part['encrypted_part'],
                        encryption_key_id=part['key_id']
                    )

                # Create a new block for the blockchain
                latest_block = Block.objects.last()
                previous_hash = latest_block.hash_block() if latest_block else "0"

                # Store part hashes in the blockchain for verification
                part_hashes = [part['part_hash'] for part in part_info]

                block_data = {
                    "file_hash": file_hash,
                    "part_hashes": part_hashes,
                    "num_parts": len(part_info)
                }

                new_block = Block.objects.create(
                    user=request.user,
                    index=latest_block.index + 1 if latest_block else 0,
                    file_hash=file_hash,
                    previous_hash=previous_hash,
                    nonce=0,
                    data=json.dumps(block_data)
                )

                messages.success(request, "File uploaded and split into secure parts successfully!")
                return redirect("file_list")

            except Exception as e:
                messages.error(request, f"Error processing file: {str(e)}")
                print(f"Error: {e}")  # Debug: Print the error

    return render(request, "fileapp/upload.html")

# Modified download_file view to reassemble file parts
@login_required
def download_file(request, file_id):
    file_upload = get_object_or_404(FileUpload, id=file_id)

    # Security check: Ensure only the owner can download
    if file_upload.user != request.user:
        return HttpResponseForbidden("You are not allowed to access this file.")

    try:
        # Reassemble the file from parts
        file_content = FileUploadManager.reassemble_file(file_upload, request.user)

        # Get original filename
        filename = os.path.basename(file_upload.file.name)

        # Create response with file content
        response = HttpResponse(file_content)
        content_type, _ = mimetypes.guess_type(filename)
        if content_type is None:
            content_type = 'application/octet-stream'

        response['Content-Type'] = content_type
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except Exception as e:
        messages.error(request, f"Error retrieving file: {str(e)}")
        return redirect('file_detail', file_id=file_id)

# Modified file_detail view to show information about file parts
@login_required
def file_detail(request, file_id):
    file_upload = get_object_or_404(FileUpload, id=file_id)

    # Security check: Ensure only the owner can access details
    if file_upload.user != request.user:
        return HttpResponseForbidden("You are not allowed to access this file.")

    # Get file parts information
    file_parts = FilePart.objects.filter(file_upload=file_upload).order_by('part_number')

    # Get blockchain verification data
    try:
        block = Block.objects.get(file_hash=file_upload.file_hash)
        block_data = json.loads(block.data)
        blockchain_verified = True
    except (Block.DoesNotExist, json.JSONDecodeError):
        block_data = {}
        blockchain_verified = False

    context = {
        'file': file_upload,
        'file_parts': file_parts,
        'part_count': file_parts.count(),
        'blockchain_verified': blockchain_verified,
        'block_data': block_data
    }

    return render(request, 'fileapp/file_detail.html', context)

def signup(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Auto-login after signup
            return redirect("file_list")
    else:
        form = UserCreationForm()
    return render(request, "fileapp/signup.html", {"form": form})

@login_required(login_url='login')  # Users must be logged in to see home
def home(request):
    return render(request, 'fileapp/home.html')

@login_required
def file_list(request):
    files = FileUpload.objects.filter(user=request.user)  # Show only user's files
    return render(request, 'fileapp/file_list.html', {'files': files})

@login_required
def search_file(request):
    query = request.GET.get('q', '')
    files = []

    if query:
        files = FileUpload.objects.filter(
            Q(file_hash__icontains=query) |
            Q(file__icontains=query),
            user=request.user  # Ensure only current user's files are shown
        )

    return render(request, 'fileapp/search.html', {'files': files, 'query': query})

def logoff_view(request):
    logout(request)
    return render(request, 'logoff.html')

def login_view(request):
    if request.user.is_authenticated:  # 🔒 Prevent logged-in users from seeing login page
        return redirect('home')  # Redirect to home or dashboard

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to home after login
        else:
            return render(request, 'fileapp/login.html', {'error': 'Invalid credentials'})

    return render(request, 'fileapp/login.html')
