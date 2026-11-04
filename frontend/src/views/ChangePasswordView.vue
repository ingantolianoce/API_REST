<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, messageFor } from '../api/http'
import { useAuth } from '../stores/auth'

const auth = useAuth()
const router = useRouter()
const current = ref('')
const next = ref('')
const error = ref('')

async function submit() {
  error.value = ''
  try {
    await api('/api/v1/auth/password', { method: 'POST', body: { currentPassword: current.value, newPassword: next.value } })
    auth.me = null // el servidor revoco TODAS las sesiones: hay que ingresar de nuevo
    await router.push('/login')
  } catch (e) {
    error.value = messageFor(e)
  }
}
</script>

<template>
  <h1>Cambiar contraseña</h1>
  <p>Use una frase larga (mínimo 15 caracteres). No se exigen símbolos ni mayúsculas, y puede usar espacios.</p>
  <form @submit.prevent="submit">
    <label for="current">Contraseña actual</label>
    <input id="current" v-model="current" type="password" autocomplete="current-password" required maxlength="256" />
    <label for="next">Nueva contraseña</label>
    <input id="next" v-model="next" type="password" autocomplete="new-password" required minlength="15" maxlength="128" />
    <button type="submit">Cambiar</button>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
  </form>
</template>
