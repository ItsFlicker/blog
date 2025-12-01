# About
pwn 萌新一枚

## 团队

<style>
    
    .users-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 25px;
        margin-bottom: 40px;
    }

    .profile-card {
        background-color: #ffffff;
        border-radius: 16px;
        padding: 25px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        border: 1px solid #f0f0f0;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    .profile-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.12);
    }

    .profile-link {
        display: flex;
        align-items: center;
        text-decoration: none;
        color: inherit;
        padding: 10px;
        border-radius: 12px;
        transition: background-color 0.3s;
    }

    .profile-link:hover {
        background-color: #f8f9fa;
    }

    .avatar {
        width: 70px;
        height: 70px;
        border-radius: 16px;
        object-fit: cover;
        border: 2px solid #f0f0f0;
        margin-right: 15px;
        transition: transform 0.3s ease;
    }

    .profile-link:hover .avatar {
        transform: scale(1.05);
    }

    .user-info {
        text-align: left;
        flex-grow: 1;
    }

    .user-id {
        font-size: 1.4rem;
        font-weight: 600;
        color: #333;
        margin-bottom: 5px;
    }

    .user-title {
        color: #666;
        font-size: 0.9rem;
    }

    .arrow {
        color: #999;
        font-size: 1.3rem;
        opacity: 0.7;
        transition: opacity 0.3s, transform 0.3s;
    }

    .profile-link:hover .arrow {
        opacity: 1;
        transform: translateX(5px);
        color: #4a6cf7;
    }

    @media (max-width: 900px) {
        .users-grid {
            grid-template-columns: repeat(2, 1fr);
        }
    }

    @media (max-width: 600px) {
        .users-grid {
            grid-template-columns: 1fr;
        }
        
        .profile-link {
            flex-direction: column;
            text-align: center;
        }
        
        .avatar {
            margin-right: 0;
            margin-bottom: 15px;
        }
        
        .user-info {
            text-align: center;
        }
    }

</style>

<div class="users-grid">
    <div class="profile-card">
        <a href="https://www.kap0k.top/" class="profile-link">
            <img src="https://www.kap0k.top/kap0k.png" alt="avatar" class="avatar">
            <div class="user-info">
            <div class="user-id">Kap0k</div>
            <div class="user-title">华南理工大学网络安全研究团队</div>
            </div>
        </a>
    </div>
</div>