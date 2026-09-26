from abc import ABC, abstractmethod


class Runtime(ABC):

    @abstractmethod
    def create(self, container_id: str) -> None:
        pass

    @abstractmethod
    def start(self, container_id: str) -> None:
        pass

    @abstractmethod
    def state(self, container_id: str) -> dict:
        pass

    @abstractmethod
    def kill(self, container_id: str, signal: int) -> None:
        pass

    @abstractmethod
    def delete(self, container_id: str) -> None:
        pass