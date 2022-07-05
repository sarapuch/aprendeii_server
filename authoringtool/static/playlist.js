const draggables = document.querySelectorAll('.draggable')
const containers = document.querySelectorAll('.playlist_container')

draggables.forEach(draggable => {
  draggable.addEventListener('dragstart', () => {
    draggable.classList.add('dragging')
  })

  draggable.addEventListener('dragend', () => {
    draggable.classList.remove('dragging')
  })
})

containers.forEach(playlist_container => {
  playlist_container.addEventListener('dragover', e => {
    e.preventDefault()
    const afterElement = getDragAfterElement(playlist_container, e.clientY)
    const draggable = document.querySelector('.dragging')
    if (afterElement == null) {
      playlist_container.appendChild(draggable)
    } else {
      playlist_container.insertBefore(draggable, afterElement)
    }
  })
})

function getDragAfterElement(playlist_container, y) {
  const draggableElements = [...playlist_container.querySelectorAll('.draggable:not(.dragging)')]

  return draggableElements.reduce((closest, child) => {
    const box = child.getBoundingClientRect()
    const offset = y - box.top - box.height / 2
    if (offset < 0 && offset > closest.offset) {
      return { offset: offset, element: child }
    } else {
      return closest
    }
  }, { offset: Number.NEGATIVE_INFINITY }).element
}


function applyOrder() {
  var playlist = document.getElementById("send").children;
  document.getElementById("playlist_size").setAttribute("value", playlist.length);

  for(var i=1; i<=playlist.length; i++){
    if(playlist[i].children[0].className == "meta_id"){
      playlist[i].children[0].setAttribute("name", "order_" + i);
    }
  }  
}