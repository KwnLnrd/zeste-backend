from flask_sqlalchemy import SQLAlchemy

# Initialisation de l'instance SQLAlchemy qui sera liée à l'application Flask
db = SQLAlchemy()

class User(db.Model):
    """
    Représente un utilisateur (restaurateur ou membre de son équipe) dans notre système.
    Ce modèle est synchronisé avec les données utilisateurs de Clerk via webhooks.
    Clerk reste la source de vérité pour l'identité.
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    # L'ID unique fourni par Clerk pour l'utilisateur. Essentiel pour la synchronisation.
    clerk_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    
    # Relation : un utilisateur peut être membre de plusieurs organisations (restaurants).
    # `back_populates` assure la synchronisation de la relation des deux côtés.
    # `cascade` garantit que si un utilisateur est supprimé, ses appartenances le sont aussi.
    memberships = db.relationship('OrganizationMembership', back_populates='user', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<User {self.clerk_id} ({self.email})>'

class Organization(db.Model):
    """
    Représente un restaurant. Dans le vocabulaire de Clerk, cela correspond à une 'Organization'.
    Ce modèle est synchronisé avec les données d'organisations de Clerk.
    """
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    # L'ID unique fourni par Clerk pour l'organisation.
    clerk_org_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True) # Le "slug" est une URL-friendly version du nom.
    
    # Relation : une organisation a plusieurs membres (utilisateurs).
    members = db.relationship('OrganizationMembership', back_populates='organization', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Organization {self.name} ({self.clerk_org_id})>'

class OrganizationMembership(db.Model):
    """
    Table de liaison (pivot) qui définit le rôle d'un utilisateur dans une organisation.
    Ce modèle est synchronisé avec les 'Memberships' de Clerk.
    """
    __tablename__ = 'organization_memberships'

    id = db.Column(db.Integer, primary_key=True)
    # L'ID unique de l'appartenance fourni par Clerk.
    clerk_membership_id = db.Column(db.String(255), unique=True, nullable=False)
    
    # Clés étrangères pointant vers les IDs de Clerk pour maintenir la cohérence.
    user_id = db.Column(db.String(255), db.ForeignKey('users.clerk_id'), nullable=False)
    organization_id = db.Column(db.String(255), db.ForeignKey('organizations.clerk_org_id'), nullable=False)
    
    # Le rôle de l'utilisateur dans l'organisation (ex: 'admin', 'basic_member').
    # Clerk utilise ces rôles pour la gestion des permissions.
    role = db.Column(db.String(50), nullable=False)

    # Relations pour accéder facilement aux objets User et Organization depuis une instance de Membership.
    user = db.relationship('User', back_populates='memberships')
    organization = db.relationship('Organization', back_populates='members')

    def __repr__(self):
        # Affiche une représentation claire de l'appartenance pour le débogage.
        # Utilise les relations pour obtenir l'email de l'utilisateur et le nom de l'organisation.
        try:
            return f'<Membership {self.user.email} in {self.organization.name} as {self.role}>'
        except AttributeError:
             return f'<Membership (pending user/org association)>'
