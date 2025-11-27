from abc import ABC, abstractmethod

class Keypair(ABC):

    # Access to Keypair components
    @abstractmethod
    def private_bytes(self) -> bytes: ...
    
    @abstractmethod
    def scalar(self) -> int: ...
    
    @abstractmethod
    def public_bytes(self) -> bytes: ...
    
    # Generate Keypair
    @abstractmethod
    def from_private_bytes(self, data: bytes) -> Keypair: ...
    
    @abstractmethod
    def generate(self) -> Keypair: ...