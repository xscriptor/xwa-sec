from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="viewer")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    domain_target = Column(String, index=True)
    status = Column(String, default="RUNNING") # RUNNING, COMPLETED, ERROR
    created_at = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String, default="port_scan") # port_scan, crawler

    # Relaciones directas (Cascada en delete)
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    discovered_links = relationship("DiscoveredLink", back_populates="scan", cascade="all, delete-orphan")

class DiscoveredLink(Base):
    __tablename__ = "discovered_links"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    url = Column(String)
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="discovered_links")
    findings = relationship("Finding", back_populates="link", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    link_id = Column(Integer, ForeignKey("discovered_links.id", ondelete="CASCADE"), nullable=True)

    severity = Column(String) # low, medium, high, info, critical
    finding_type = Column(String)
    description = Column(String)
    poc_payload = Column(String, nullable=True)  # Changed to unlimited text
    cvss_score = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")
    link = relationship("DiscoveredLink", back_populates="findings")


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    scan_type = Column(String(32), nullable=False)  # port_scan | web_recon | vuln_crawl
    target = Column(String(2048), nullable=False)
    config_json = Column(Text, nullable=False, default="{}")  # scan-type-specific params
    cron_expression = Column(String(128), nullable=False)
    is_enabled = Column(Boolean, nullable=False, default=True)
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)

    created_by = relationship("User", foreign_keys=[created_by_id])
    last_scan = relationship("Scan", foreign_keys=[last_scan_id])
